package hash_miner

import (
	"bytes"
	"container/list"
	"crypto/md5"
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
	queue := list.New()
	startingArr := new(bytes.Buffer)
	startingArr.WriteByte(startingPrefix << (8-threadBits))
	if checkMinedValue(nonce, numTrailingZeroes, startingArr.Bytes()) {
		success := WorkerSuccess{startingPrefix, startingArr.Bytes()}
		tracer.RecordAction(success)
		succeeded <-success
		return
	}
	queue.PushBack(startingArr.Bytes())
	startingArr.Reset()
	//fmt.Printf("q: %#b\n", queue[0][0])
	// check if starting suffix is enough
	// Handle first byte
	// 2^(8-threadbits) * 2^(8-threadbits) to do

	for i := 0; i < int(math.Exp2(float64(8-threadBits))); i++ {
		if foundAns {
			tracer.RecordAction(WorkerCancelled{startingPrefix})
			return
		}
		cpy := make([]uint8, len(queue.Front().Value.([]byte)))
		copy(cpy, queue.Front().Value.([]byte))
		cpy[0] |= uint8(i)
		// check if correct hash
		if checkMinedValue(nonce, numTrailingZeroes, cpy) {
			success := WorkerSuccess{startingPrefix, cpy}
			tracer.RecordAction(success)
			succeeded <-success
			return
		}
		queue.PushBack(cpy)
	}
	queue.Remove(queue.Front())

	for {
		if foundAns {
			tracer.RecordAction(WorkerCancelled{startingPrefix})
			return
		}

		for i := 0; i < 0x100; i++ {
			if foundAns {
				tracer.RecordAction(WorkerCancelled{startingPrefix})
				return
			}
			curSecret := new(bytes.Buffer)
			curSecret.Write(queue.Front().Value.([]byte))
			curSecret.WriteByte(reverseBits(byte(i)))
			if checkMinedValue(nonce, numTrailingZeroes, curSecret.Bytes()) {
				success := WorkerSuccess{startingPrefix, curSecret.Bytes()}
				foundAns = true
				tracer.RecordAction(success)
				succeeded <- success
				close(succeeded)
				return
			}
			queue.PushBack(curSecret.Bytes())
			curSecret.Reset()
		}
		queue.Remove(queue.Front())
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
	var waitgroup sync.WaitGroup
	for i := 0; i < int(math.Exp2(float64(threadBits))); i++ {
		waitgroup.Add(1)
		go mineWorker(&waitgroup, tracer, uint8(i), nonce, numTrailingZeroes, threadBits)
	}
	success := <-succeeded
	waitgroup.Wait()
	result := success.Secret

	tracer.RecordAction(MiningComplete{result})
	return result, nil
}
