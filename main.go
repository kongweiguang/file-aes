package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// 缓冲区和块大小常量
const (
	// 默认读写缓冲区大小 (4MB)
	defaultBufferSize = 4 * 1024 * 1024
	// 处理块大小 (1MB)
	chunkSize = 1 * 1024 * 1024
	// 进度更新间隔 (毫秒)
	progressUpdateInterval = 100
)

// 使用系统CPU核心数作为默认工作线程数
var cpuNum = runtime.NumCPU()

// Job 表示一个加密/解密任务
type Job struct {
	chunk     []byte // 输入数据块
	outChunk  []byte // 输出数据块
	chunkSize int    // 实际数据大小
	index     int    // 块索引，用于保持顺序
}

// 文件处理模式
type ProcessMode int

const (
	EncryptMode ProcessMode = iota
	DecryptMode
)

// 主函数
func main() {
	// 定义命令行参数
	encryptFlag := flag.Bool("e", false, "加密模式")
	decryptFlag := flag.Bool("d", false, "解密模式")
	keyString := flag.String("k", "", "16, 24 或 32 字节的密钥（十六进制字符串）")
	inputFile := flag.String("i", "", "输入文件路径")
	outputFile := flag.String("o", "", "输出文件路径")

	flag.Parse()

	// 检查必要参数
	if (!*encryptFlag && !*decryptFlag) || *keyString == "" || *inputFile == "" {
		fmt.Println("用法: program [-e|-d] -k <密钥> -i <输入文件> [-o <输出文件>]")
		flag.PrintDefaults()
		return
	}

	// 准备密钥
	key, err := hex.DecodeString(*keyString)
	if err != nil || (len(key) != 16 && len(key) != 24 && len(key) != 32) {
		fmt.Println("错误: 密钥必须是16, 24或32字节的十六进制字符串")
		return
	}

	// 设置默认输出文件名
	if *outputFile == "" {
		if *encryptFlag {
			*outputFile = *inputFile + ".enc"
		} else {
			*outputFile = "dec_" + filepath.Base(*inputFile)
		}
	}

	// 根据模式执行相应操作
	startTime := time.Now()
	var processedBytes int64
	var mode ProcessMode

	if *encryptFlag {
		mode = EncryptMode
	} else {
		mode = DecryptMode
	}

	// 处理文件
	processedBytes, err = processFile(*inputFile, *outputFile, key, mode)
	if err != nil {
		fmt.Printf("错误: %v\n", err)
		return
	}

	// 输出处理结果
	duration := time.Since(startTime)
	printResults(processedBytes, duration)
}

// 打印处理结果
func printResults(processedBytes int64, duration time.Duration) {
	fmt.Printf("文件处理完成!\n")
	fmt.Printf("处理了 %.2f MB\n", float64(processedBytes)/(1024*1024))
	fmt.Printf("耗时: %v\n", duration)
	fmt.Printf("速度: %.2f MB/s\n", float64(processedBytes)/(1024*1024)/duration.Seconds())
}

// 处理文件（加密或解密）
func processFile(inputPath, outputPath string, key []byte, mode ProcessMode) (int64, error) {
	// 打开输入文件
	inFile, err := os.Open(inputPath)
	if err != nil {
		return 0, fmt.Errorf("无法打开输入文件: %w", err)
	}
	defer inFile.Close()

	// 获取文件大小以便显示进度
	fileInfo, err := inFile.Stat()
	if err != nil {
		return 0, fmt.Errorf("无法获取文件信息: %w", err)
	}
	fileSize := fileInfo.Size()

	// 创建输出文件
	outFile, err := os.Create(outputPath)
	if err != nil {
		return 0, fmt.Errorf("无法创建输出文件: %w", err)
	}
	defer outFile.Close()

	// 创建AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, fmt.Errorf("创建AES cipher失败: %w", err)
	}

	// 处理IV（初始化向量）
	iv := make([]byte, aes.BlockSize)
	if mode == EncryptMode {
		// 加密模式：生成随机IV
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return 0, fmt.Errorf("生成IV失败: %w", err)
		}
	} else {
		// 解密模式：从文件读取IV
		if _, err := io.ReadFull(inFile, iv); err != nil {
			return 0, fmt.Errorf("读取IV失败: %w", err)
		}
		// 调整文件大小（减去IV长度）
		fileSize -= int64(len(iv))
	}

	// 创建带缓冲的读取器和写入器
	bufReader := bufio.NewReaderSize(inFile, defaultBufferSize)
	bufWriter := bufio.NewWriterSize(outFile, defaultBufferSize)
	defer bufWriter.Flush()

	// 如果是加密模式，写入IV到输出文件开头
	if mode == EncryptMode {
		if _, err := bufWriter.Write(iv); err != nil {
			return 0, fmt.Errorf("写入IV失败: %w", err)
		}
	}

	// 设置进度更新间隔
	progressInterval := time.NewTicker(progressUpdateInterval * time.Millisecond)
	defer progressInterval.Stop()

	// 创建工作线程池和通道
	jobs := make(chan Job, cpuNum*2)
	results := make(chan Job, cpuNum*2)
	errChan := make(chan error, 1)

	var wg sync.WaitGroup
	var totalProcessed int64

	// 打印初始进度
	operationName := "加密"
	if mode == DecryptMode {
		operationName = "解密"
	}
	fmt.Printf("正在%s文件: %s (%.2f MB)\n", operationName, inputPath, float64(fileSize)/(1024*1024))

	// 启动进度显示goroutine
	go displayProgress(progressInterval, &totalProcessed, fileSize)

	// 启动工作线程
	for i := 0; i < cpuNum; i++ {
		wg.Add(1)
		go processWorker(i, block, iv, jobs, results, &wg)
	}

	// 启动结果写入goroutine
	go writeResults(results, bufWriter, &totalProcessed, errChan)

	// 读取数据并创建任务
	index := 0
	for {
		chunk := make([]byte, chunkSize)
		outChunk := make([]byte, chunkSize)

		n, err := bufReader.Read(chunk)
		if err != nil && err != io.EOF {
			return totalProcessed, fmt.Errorf("读取输入文件失败: %w", err)
		}
		if n == 0 {
			break
		}

		select {
		case err := <-errChan:
			// 如果有错误发生，立即返回
			if err != nil {
				return totalProcessed, err
			}
		default:
			// 否则继续发送任务
			jobs <- Job{
				chunk:     chunk,
				outChunk:  outChunk,
				chunkSize: n,
				index:     index,
			}
			index++
		}
	}

	// 关闭任务通道
	close(jobs)

	// 等待所有工作线程完成
	wg.Wait()

	// 关闭结果通道
	close(results)

	// 检查是否有错误
	if err := <-errChan; err != nil {
		return totalProcessed, err
	}

	// 确保所有数据都已写入文件
	if err := bufWriter.Flush(); err != nil {
		return totalProcessed, fmt.Errorf("刷新写入缓冲区失败: %w", err)
	}

	// 显示最终进度
	printFinalProgress(totalProcessed, fileSize)

	// 输出完成信息
	fmt.Printf("\n%s完成！\n", operationName)
	return totalProcessed, nil
}

// 显示进度
func displayProgress(ticker *time.Ticker, totalProcessed *int64, fileSize int64) {
	for range ticker.C {
		current := atomic.LoadInt64(totalProcessed)
		if fileSize > 0 {
			fmt.Printf("\r进度: %.2f%% (%.2f/%.2f MB)", float64(current)*100/float64(fileSize),
				float64(current)/(1024*1024), float64(fileSize)/(1024*1024))
		} else {
			fmt.Printf("\r已处理: %.2f MB", float64(current)/(1024*1024))
		}
	}
}

// 打印最终进度
func printFinalProgress(totalProcessed int64, fileSize int64) {
	if fileSize > 0 {
		fmt.Printf("\r进度: 100.00%% (%.2f/%.2f MB)", float64(totalProcessed)/(1024*1024), float64(fileSize)/(1024*1024))
	} else {
		fmt.Printf("\r已处理: %.2f MB", float64(totalProcessed)/(1024*1024))
	}
}

// 工作线程函数
func processWorker(workerId int, block cipher.Block, iv []byte, jobs <-chan Job, results chan<- Job, wg *sync.WaitGroup) {
	defer wg.Done()

	// 为每个工作线程创建一个独立的IV副本
	workerIV := make([]byte, aes.BlockSize)
	copy(workerIV, iv)

	// 每个工作线程处理的任务
	for job := range jobs {
		// 根据索引计算当前块的IV偏移
		blockIV := make([]byte, aes.BlockSize)
		copy(blockIV, workerIV)

		// 调整IV以匹配当前块位置
		adjustIVForBlock(blockIV, job.index)

		// 创建CTR模式加密/解密器
		stream := cipher.NewCTR(block, blockIV)

		// 对当前块进行加密/解密
		stream.XORKeyStream(job.outChunk[:job.chunkSize], job.chunk[:job.chunkSize])

		// 发送结果
		results <- job
	}
}

// 调整IV以匹配块位置
func adjustIVForBlock(iv []byte, blockIndex int) {
	for i := 0; i < blockIndex; i++ {
		for j := len(iv) - 1; j >= 0; j-- {
			iv[j]++
			if iv[j] != 0 {
				break
			}
		}
	}
}

// 写入结果
func writeResults(results <-chan Job, writer *bufio.Writer, totalProcessed *int64, errChan chan<- error) {
	// 保存结果顺序
	resultMap := make(map[int][]byte)
	nextIndex := 0

	for job := range results {
		// 将结果存入映射
		resultMap[job.index] = job.outChunk[:job.chunkSize]

		// 尝试按顺序写入结果
		for {
			data, exists := resultMap[nextIndex]
			if !exists {
				break
			}

			_, err := writer.Write(data)
			if err != nil {
				select {
				case errChan <- fmt.Errorf("写入数据失败: %w", err):
				default:
				}
				return
			}

			atomic.AddInt64(totalProcessed, int64(len(data)))
			delete(resultMap, nextIndex)
			nextIndex++
		}
	}

	// 关闭错误通道，表示所有工作已完成
	close(errChan)
}
