package hash_miner

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"github.com/DistributedClocks/tracing"
	"math"
	"strings"
)

type WorkerStart struct {
	ThreadByte uint8
}

type WorkerSuccess struct {
	ThreadByte uint8
	Secret     []uint8
}

type WorkerCancelled struct {
	ThreadByte uint8
}

type MiningBegin struct{}

type MiningComplete struct {
	Secret []uint8
}

var succeeded = make(chan WorkerSuccess)

func mineWorker(tracer *tracing.Tracer, startingPrefix uint8, nonce []uint8, numTrailingZeroes uint, threadBits uint) {
	tracer.RecordAction(WorkerStart{startingPrefix})
	queue := make([][]uint8, 0)
	startingArr := new(bytes.Buffer)
	startingArr.WriteByte(startingPrefix << (8-threadBits))
	if checkMinedValue(nonce, numTrailingZeroes, startingArr.Bytes()) {
		success := WorkerSuccess{startingPrefix, startingArr.Bytes()}
		tracer.RecordAction(success)
		succeeded <-success
		return
	}
	queue = append(queue, startingArr.Bytes())

	//fmt.Printf("q: %#b\n", queue[0][0])
	// check if starting suffix is enough
	// Handle first byte
	// 2^(8-threadbits) * 2^(8-threadbits) to do

	for i := 0; i < int(math.Exp2(float64(8-threadBits))); i++ {
		select {
		case <-succeeded:
			tracer.RecordAction(WorkerCancelled{startingPrefix})
			return
		default:
			cpy := make([]uint8, len(queue[0]))
			copy(cpy, queue[0])
			cpy[0] |= uint8(i)
			// check if correct hash
			if checkMinedValue(nonce, numTrailingZeroes, cpy) {
				success := WorkerSuccess{startingPrefix, cpy}
				tracer.RecordAction(success)
				succeeded <-success
				return
			}
			queue = append(queue, cpy)
		}
	}
	queue = queue[1:]

	for {
		select {
		case <-succeeded:
			tracer.RecordAction(WorkerCancelled{startingPrefix})
			return
		default:
			for i := 0; i < 0x100; i++ {
				select {
				case <-succeeded:
					tracer.RecordAction(WorkerCancelled{startingPrefix})
					return
				default:
					curSecret := new(bytes.Buffer)
					curSecret.Write(queue[0])
					curSecret.WriteByte(reverseBits(byte(i)))
					if checkMinedValue(nonce, numTrailingZeroes, curSecret.Bytes()) {
						success := WorkerSuccess{startingPrefix, curSecret.Bytes()}
						tracer.RecordAction(success)
						succeeded <- success
						return
					}
					queue = append(queue, curSecret.Bytes())
				}
			}
			queue = queue[1:]
		}
	}
}

func reverseBits(b byte) byte{
	b = (b & 0xF0) >> 4 | (b & 0x0F) << 4
	b = (b & 0xCC) >> 2 | (b & 0x33) << 2
	b = (b & 0xAA) >> 1 | (b & 0x55) << 1
	return b
}

func checkMinedValue(nonce []uint8, numTrailingZeroes uint, secret []uint8) bool {
	select {
	case <-succeeded:
		return false
	default:
		var compareString string
		for i := uint(0); i < numTrailingZeroes; i++ {
			compareString += "0"
		}
		concat := append(nonce, secret...)
		checksum := md5.Sum(concat)
		hashString := fmt.Sprintf("%x", checksum)
		return strings.HasSuffix(hashString, compareString)
	}
}

func Mine(tracer *tracing.Tracer, nonce []uint8, numTrailingZeroes, threadBits uint) (secret []uint8, err error) {
	tracer.RecordAction(MiningBegin{})

	// TODO

	for i := uint8(0); i < uint8(math.Exp2(float64(threadBits))); i++ {
		go mineWorker(tracer, i, nonce, numTrailingZeroes, threadBits)
	}
	success := <-succeeded
	result := success.Secret
	tracer.RecordAction(MiningComplete{result})

	return result, nil
}
