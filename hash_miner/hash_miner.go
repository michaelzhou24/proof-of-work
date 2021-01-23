package hash_miner

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"github.com/DistributedClocks/tracing"
	"math"
	"strings"
	"sync"
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
var foundAns bool = false
func mineWorker(waitgroup *sync.WaitGroup, tracer *tracing.Tracer, startingPrefix uint8, nonce []uint8, numTrailingZeroes uint, threadBits uint) {
	defer waitgroup.Done()
	tracer.RecordAction(WorkerStart{startingPrefix})
	firstByteCombos := make([][]byte, 0)
	startingArr := new(bytes.Buffer)
	startingArr.WriteByte(startingPrefix << (8-threadBits))
	if checkMinedValue(nonce, numTrailingZeroes, startingArr.Bytes()) {
		success := WorkerSuccess{startingPrefix, startingArr.Bytes()}
		tracer.RecordAction(success)
		succeeded <-success
		return
	}
	firstByteCombos = append(firstByteCombos, startingArr.Bytes())
	//fmt.Printf("q: %#b\n", firstByteCombos[0][0])
	// check if starting suffix is enough
	// Handle first byte
	// 2^(8-threadbits) * 2^(8-threadbits) to do

	for i := 0; i < int(math.Exp2(float64(8-threadBits))); i++ {
		if foundAns {
			tracer.RecordAction(WorkerCancelled{startingPrefix})
			return
		}
		cpy := make([]uint8, len(firstByteCombos[0]))
		copy(cpy, firstByteCombos[0])
		cpy[0] |= uint8(i)
		// check if correct hash
		if checkMinedValue(nonce, numTrailingZeroes, cpy) {
			success := WorkerSuccess{startingPrefix, cpy}
			foundAns = true
			tracer.RecordAction(success)
			succeeded <-success
			return
		}
		firstByteCombos = append(firstByteCombos, cpy)
	}

	for i := uint64(0); i < math.MaxUint64; i++ {
		for idx := 0; idx < len(firstByteCombos); idx++ {
			if foundAns {
				tracer.RecordAction(WorkerCancelled{startingPrefix})
				return
			}
			buf := new(bytes.Buffer)
			buf.WriteByte(firstByteCombos[idx][0])
			if i <= math.MaxUint8 {
				_ = binary.Write(buf, binary.LittleEndian, uint8(i))
			} else if i <= math.MaxUint16 {
				_ = binary.Write(buf, binary.LittleEndian, uint16(i))
			} else if i <= math.MaxUint32 {
				_ = binary.Write(buf, binary.LittleEndian, uint32(i))
			} else {
				_ = binary.Write(buf, binary.LittleEndian, i)
			}
			if checkMinedValue(nonce, numTrailingZeroes, buf.Bytes()) {
				success := WorkerSuccess{startingPrefix, buf.Bytes()}
				foundAns = true
				tracer.RecordAction(success)
				succeeded <-success
				return
			}
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
	if foundAns {
		return false
	}

	var compareString string
	for i := uint(0); i < numTrailingZeroes; i++ {
		compareString += "0"
	}
	concat := append(nonce, secret...)
	checksum := md5.Sum(concat)
	hashString := fmt.Sprintf("%x", checksum)
	return strings.HasSuffix(hashString, compareString)

}

func Mine(tracer *tracing.Tracer, nonce []uint8, numTrailingZeroes, threadBits uint) (secret []uint8, err error) {
	tracer.RecordAction(MiningBegin{})

	// TODO
	var success = WorkerSuccess{0, nil}
	var waitgroup sync.WaitGroup
	flag := 0
	for i := 0; i < int(math.Exp2(float64(threadBits))); i++ {
		if flag == 1 {
			break
		}
		select {
			case success = <-succeeded:
				flag = 1
				break
			default:
				waitgroup.Add(1)
				go mineWorker(&waitgroup, tracer, uint8(i), nonce, numTrailingZeroes, threadBits)
		}
	}
	if success.Secret == nil {
		success = <-succeeded
	}
	waitgroup.Wait()
	result := success.Secret

	tracer.RecordAction(MiningComplete{result})
	return result, nil
}
