package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	netURL "net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valyala/fasthttp"
)

var (
	requests         int64
	period           int64
	clients          int
	url              string
	urlsFilePath     string
	keepAlive        bool
	postDataFilePath string
	writeTimeout     int
	readTimeout      int
	authHeader       string
)

var (
	kexAlgo = flag.String("benchkex", "P256_Kyber512", "Kex algorithm")
	authAlgo = flag.String("benchauth", "P256_Dilithium2", "Authentication algorithm")
)

type Configuration struct {
	urls       []string
	method     string
	postData   []byte
	requests   int64
	period     int64
	keepAlive  bool
	authHeader string

	myClient fasthttp.Client
}

type Result struct {
	requests      int64
	success       int64
	networkFailed int64
	badFailed     int64
}

var readThroughput int64
var writeThroughput int64

type MyConn struct {
	net.Conn
}

func (this *MyConn) Read(b []byte) (n int, err error) {
	len, err := this.Conn.Read(b)

	if err == nil {
		atomic.AddInt64(&readThroughput, int64(len))
	}

	return len, err
}

func (this *MyConn) Write(b []byte) (n int, err error) {
	len, err := this.Conn.Write(b)

	if err == nil {
		atomic.AddInt64(&writeThroughput, int64(len))
	}

	return len, err
}

func init() {
	flag.Int64Var(&requests, "r", -1, "Number of requests per client")
	flag.IntVar(&clients, "c", 100, "Number of concurrent clients")
	flag.StringVar(&url, "u", "", "URL")
	flag.StringVar(&urlsFilePath, "f", "", "URL's file path (line seperated)")
	flag.BoolVar(&keepAlive, "k", true, "Do HTTP keep-alive")
	flag.StringVar(&postDataFilePath, "d", "", "HTTP POST data file path")
	flag.Int64Var(&period, "t", -1, "Period of time (in seconds)")
	flag.IntVar(&writeTimeout, "tw", 5000, "Write timeout (in milliseconds)")
	flag.IntVar(&readTimeout, "tr", 5000, "Read timeout (in milliseconds)")
	flag.StringVar(&authHeader, "auth", "", "Authorization header")
}

func getHostFromURL(url string) string {
	u, err := netURL.Parse(url)
	if err != nil {
		panic(err)
	}

	host, _, err := net.SplitHostPort(u.Host)	
	if err != nil {
		panic(err)
	}
	return host
}

func saveLoadTestCSV(kemName, authName string, results map[int]*Result, elapsed, readThroughput, writeThroughput int64) {
	var requests int64
	var success int64
	var networkFailed int64
	var badFailed int64

	for _, result := range results {
		requests += result.requests
		success += result.success
		networkFailed += result.networkFailed
		badFailed += result.badFailed
	}

	var fileName string

	if *pqtls {
		if *cachedCert {
			fileName = "csv/load_test_pqtls_cached_cert.csv"
		} else {
			fileName = "csv/load_test_pqtls.csv"
		}		
	} else {
		if *cachedCert {
			fileName = "csv/load_test_kemtls_pdk.csv"
		} else {
			fileName = "csv/load_test_kemtls.csv"
		}		
	}

	if _, err := os.Stat(fileName); errors.Is(err, os.ErrNotExist) {
		csvFile, err := os.Create(fileName)
		if err != nil {
			panic(err)
		}
		csvwriter := csv.NewWriter(csvFile)

		header := []string{"KEX", "Auth", "Number of clients", "Requests", "Successful requests", "Network failed", "Bad requests failed (!2xx)", "Successful requests rate (hits/sec)", "Read throughput (bytes/sec)", "Write throughput (bytes/sec)", "Test time (sec)"}
		if err := csvwriter.Write(header); err != nil {
			panic(err)
		}
		csvwriter.Flush()
		csvFile.Close()		
	}

	csvFile, err := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		panic(err)
	}
	
	csvwriter := csv.NewWriter(csvFile)
	
	arrayStr := []string{
		kemName, authName,
		fmt.Sprintf("%d", clients), 
		fmt.Sprintf("%d", requests), 
		fmt.Sprintf("%d", success), 
		fmt.Sprintf("%d", networkFailed),
		fmt.Sprintf("%d", badFailed),
		fmt.Sprintf("%d", success/elapsed),
		fmt.Sprintf("%d", readThroughput/elapsed),
		fmt.Sprintf("%d", writeThroughput/elapsed),
		fmt.Sprintf("%d", elapsed),
	}

	if err := csvwriter.Write(arrayStr); err != nil {
		panic(err)
	}

	csvwriter.Flush()
	csvFile.Close()

	fmt.Println()
	fmt.Printf("Requests:                       %10d hits\n", requests)
	fmt.Printf("Successful requests:            %10d hits\n", success)
	fmt.Printf("Network failed:                 %10d hits\n", networkFailed)
	fmt.Printf("Bad requests failed (!2xx):     %10d hits\n", badFailed)
	fmt.Printf("Successful requests rate:       %10d hits/sec\n", success/elapsed)
	fmt.Printf("Read throughput:                %10d bytes/sec\n", readThroughput/elapsed)
	fmt.Printf("Write throughput:               %10d bytes/sec\n", writeThroughput/elapsed)
	fmt.Printf("Test time:                      %10d sec\n", elapsed)
}



func saveResultsAndNotifyServer(results map[int]*Result, startTime time.Time) {
	elapsed := int64(time.Since(startTime).Seconds())

	if elapsed == 0 {
		elapsed = 1
	}

	saveLoadTestCSV(*kexAlgo, *authAlgo,  results, elapsed, readThroughput, writeThroughput)	
	
	if *synchronize {
		notify("FINISHED", getHostFromURL(url), serverNotificationPort)    
  }
}

func readLines(path string) (lines []string, err error) {

	var file *os.File
	var part []byte
	var prefix bool

	if file, err = os.Open(path); err != nil {
		return
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	buffer := bytes.NewBuffer(make([]byte, 0))
	for {
		if part, prefix, err = reader.ReadLine(); err != nil {
			break
		}
		buffer.Write(part)
		if !prefix {
			lines = append(lines, buffer.String())
			buffer.Reset()
		}
	}
	if err == io.EOF {
		err = nil
	}
	return
}

func NewConfiguration() *Configuration {

	if urlsFilePath == "" && url == "" {
		flag.Usage()
		os.Exit(1)
	}

	if requests == -1 && period == -1 {
		fmt.Println("Requests or period must be provided")
		flag.Usage()
		os.Exit(1)
	}

	if requests != -1 && period != -1 {
		fmt.Println("Only one should be provided: [requests|period]")
		flag.Usage()
		os.Exit(1)
	}

	configuration := &Configuration{
		urls:       make([]string, 0),
		method:     "GET",
		postData:   nil,
		keepAlive:  keepAlive,
		requests:   int64((1 << 63) - 1),
		authHeader: authHeader}

	if period != -1 {
		configuration.period = period

		timeout := make(chan bool, 1)
		go func() {
			<-time.After(time.Duration(period) * time.Second)
			timeout <- true
		}()

		go func() {
			<-timeout
			pid := os.Getpid()
			proc, _ := os.FindProcess(pid)
			err := proc.Signal(os.Interrupt)
			if err != nil {
				log.Println(err)
				return
			}
		}()
	}

	if requests != -1 {
		configuration.requests = requests
	}

	if urlsFilePath != "" {
		fileLines, err := readLines(urlsFilePath)

		if err != nil {
			log.Fatalf("Error in ioutil.ReadFile for file: %s Error: ", urlsFilePath, err)
		}

		configuration.urls = fileLines
	}

	if url != "" {
		configuration.urls = append(configuration.urls, url)
	}

	if postDataFilePath != "" {
		configuration.method = "POST"

		data, err := ioutil.ReadFile(postDataFilePath)

		if err != nil {
			log.Fatalf("Error in ioutil.ReadFile for file path: %s Error: ", postDataFilePath, err)
		}

		configuration.postData = data
	}

	configuration.myClient.ReadTimeout = time.Duration(readTimeout) * time.Millisecond
	configuration.myClient.WriteTimeout = time.Duration(writeTimeout) * time.Millisecond
	configuration.myClient.MaxConnsPerHost = clients

	configuration.myClient.Dial = MyDialer()

	var err error
	
	configuration.myClient.TLSConfig, err = initConfigurationAndCertChain(*kexAlgo, *authAlgo, true)	
	if err != nil {
		log.Fatalf("Error in initClientAndAuth: ", err)
	}
	if configuration.myClient.TLSConfig == nil {
		log.Fatal("Error in initClientAndAuth: result config is nil")
	}
	
	if *cachedCert {

		u, err := netURL.Parse(url)
		if err != nil {
			panic(err)
		}

		host, port, _ := net.SplitHostPort(u.Host)	
		
		portInt, err := strconv.Atoi(port)
		if err != nil {
			panic(err)
		}		

		portInt = portInt + 1
		port = strconv.Itoa(portInt)		

		client, err := tls.Dial("tcp", host+":"+port, configuration.myClient.TLSConfig)
		if err != nil {
			fmt.Print(err)
		}
		defer client.Close()

		cconnState := client.ConnectionState()
				
		if err != nil {
			fmt.Println("Error establishing first connection for cached certificate mode")
			log.Fatal(err)
		} else {
			fmt.Println("Success establishing first connection for cached certificate mode")
		}

		configuration.myClient.TLSConfig.CachedCert = cconnState.CertificateMessage		
	}
			
	return configuration
}

func MyDialer() func(address string) (conn net.Conn, err error) {
	return func(address string) (net.Conn, error) {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			return nil, err
		}

		myConn := &MyConn{Conn: conn}

		return myConn, nil
	}
}

func client(configuration *Configuration, result *Result, done *sync.WaitGroup) {
	for result.requests < configuration.requests {
		for _, tmpUrl := range configuration.urls {

			req := fasthttp.AcquireRequest()

			req.SetRequestURI(tmpUrl)
			req.Header.SetMethodBytes([]byte(configuration.method))

			if configuration.keepAlive == true {
				req.Header.Set("Connection", "keep-alive")
			} else {
				req.Header.Set("Connection", "close")
			}

			if len(configuration.authHeader) > 0 {
				req.Header.Set("Authorization", configuration.authHeader)
			}

			req.SetBody(configuration.postData)

			resp := fasthttp.AcquireResponse()
			err := configuration.myClient.Do(req, resp)
			statusCode := resp.StatusCode()
			result.requests++
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)

			if err != nil {
				result.networkFailed++
				continue
			}

			if statusCode == fasthttp.StatusOK {
				result.success++
			} else {
				result.badFailed++
			}
		}
	}

	done.Done()
}

func main() {	

	flag.Parse()

	// if *synchronize {
	// 	if *cachedCert {
	// 		waitNotification("CACHED CERT TEMP SERVER IS READY", *IPclient, clientNotificationPort)
	// 	} else {
	// 		waitNotification("SERVERS ARE READY", getHostFromURL(url), clientNotificationPort)
	// 	}
	// }
	

	startTime := time.Now()
	var done sync.WaitGroup
	results := make(map[int]*Result)

	signalChannel := make(chan os.Signal, 2)
	signal.Notify(signalChannel, os.Interrupt)
	go func() {
		_ = <-signalChannel
		saveResultsAndNotifyServer(results, startTime)
		os.Exit(0)
	}()
	

	configuration := NewConfiguration()

	// if *synchronize && *cachedCert {
	// 	waitNotification("SERVERS ARE READY", getHostFromURL(url), clientNotificationPort)
	// }

	goMaxProcs := os.Getenv("GOMAXPROCS")

	if goMaxProcs == "" {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	fmt.Printf("Dispatching %d clients\n", clients)

	done.Add(clients)
	for i := 0; i < clients; i++ {
		result := &Result{}
		results[i] = result
		go client(configuration, result, &done)

	}
	fmt.Println("Waiting for results...")
	done.Wait()
	saveResultsAndNotifyServer(results, startTime)
}
