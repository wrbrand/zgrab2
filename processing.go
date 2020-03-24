package zgrab2

import (
  "encoding/json"
  "fmt"
  "net"
  "sync"
  "runtime"
  "time"
  log "github.com/sirupsen/logrus"
  "github.com/zmap/zgrab2/lib/output"
)

/*
#define _GNU_SOURCE
#include <sched.h>
#include <pthread.h>

void lock_thread(int cpuid) {
  pthread_t tid;
  cpu_set_t cpuset;

  tid = pthread_self();
  CPU_ZERO(&cpuset);
  CPU_SET(cpuid, &cpuset);
  pthread_setaffinity_np(tid, sizeof(cpu_set_t), &cpuset);
}
*/
import "C"

// http://pythonwise.blogspot.com/2019/03/cpu-affinity-in-go.html?m=1 ; 
func setAffinity(cpuID int) {
  runtime.LockOSThread()
  C.lock_thread(C.int(cpuID))
}

// Grab contains all scan responses for a single host
type Grab struct {
  IP     string                  `json:"ip,omitempty"`
  Domain string                  `json:"domain,omitempty"`
  Data   map[string]*ScanResponse `json:"data,omitempty"`
}

// ScanTarget is the host that will be scanned
type ScanTarget struct {
  IP     net.IP
  Domain string
  Tag    string
  Port   *uint
}

func (target ScanTarget) String() string {
  if target.IP == nil && target.Domain == "" {
    return "<empty target>"
  }
  res := ""
  if target.IP != nil && target.Domain != "" {
    res = target.Domain + "(" + target.IP.String() + ")"
  } else if target.IP != nil {
    res = target.IP.String()
  } else {
    res = target.Domain
  }
  if target.Tag != "" {
    res += " tag:" + target.Tag
  }
  return res
}

// Host gets the host identifier as a string: the IP address if it is available,
// or the domain if not.
func (target *ScanTarget) Host() string {
  if target.IP != nil {
    return target.IP.String()
  } else if target.Domain != "" {
    return target.Domain
  }
  log.Fatalf("Bad target %s: no IP/Domain", target.String())
  panic("unreachable")
}

// Open connects to the ScanTarget using the configured flags, and returns a net.Conn that uses the configured timeouts for Read/Write operations.
func (target *ScanTarget) Open(flags *BaseFlags) (net.Conn, error) {
  var port uint
  // If the port is supplied in ScanTarget, let that override the cmdline option
  if target.Port != nil {
    port = *target.Port
  } else {
    port = flags.Port
  }

  address := net.JoinHostPort(target.Host(), fmt.Sprintf("%d", port))
  return DialTimeoutConnection("tcp", address, flags.Timeout, flags.BytesReadLimit)
}

// OpenTLS connects to the ScanTarget using the configured flags, then performs
// the TLS handshake. On success error is nil, but the connection can be non-nil
// even if there is an error (this allows fetching the handshake log).
func (target *ScanTarget) OpenTLS(baseFlags *BaseFlags, tlsFlags *TLSFlags) (*TLSConnection, error) {
  conn, err := tlsFlags.Connect(target, baseFlags)
  if err != nil {
    return conn, err
  }
  err = conn.Handshake()
  return conn, err
}

// OpenUDP connects to the ScanTarget using the configured flags, and returns a net.Conn that uses the configured timeouts for Read/Write operations.
// Note that the UDP "connection" does not have an associated timeout.
func (target *ScanTarget) OpenUDP(flags *BaseFlags, udp *UDPFlags) (net.Conn, error) {
  var port uint
  // If the port is supplied in ScanTarget, let that override the cmdline option
  if target.Port != nil {
    port = *target.Port
  } else {
    port = flags.Port
  }
  address := net.JoinHostPort(target.Host(), fmt.Sprintf("%d", port))
  var local *net.UDPAddr
  if udp != nil && (udp.LocalAddress != "" || udp.LocalPort != 0) {
    local = &net.UDPAddr{}
    if udp.LocalAddress != "" && udp.LocalAddress != "*" {
      local.IP = net.ParseIP(udp.LocalAddress)
    }
    if udp.LocalPort != 0 {
      local.Port = int(udp.LocalPort)
    }
  }
  remote, err := net.ResolveUDPAddr("udp", address)
  if err != nil {
    return nil, err
  }
  conn, err := net.DialUDP("udp", local, remote)
  if err != nil {
    return nil, err
  }
  return NewTimeoutConnection(nil, conn, flags.Timeout, 0, 0, flags.BytesReadLimit), nil
}

// grabTarget calls handler for each action
func grabTarget(input ScanTarget, m *Monitor) *[]byte {
  moduleResult := make(map[string]*ScanResponse)

  for _, scannerName := range orderedScanners {
    scanner := scanners[scannerName]
    trigger := (*scanner).GetTrigger()
    if input.Tag != trigger {
      continue
    }
    defer func(name string) {
      if e := recover(); e != nil {
        log.Errorf("Panic on scanner %s when scanning target %s: %#v", scannerName, input.String(), e)
        // Bubble out original error (with original stack) in lieu of explicitly logging the stack / error
        panic(e)
      }
    }(scannerName)
    name, res := RunScanner(*scanner, m, input)
    moduleResult[name] = res
    if res.Error != nil && !config.Multiple.ContinueOnError {
      break
    }
    if res.Status == SCAN_SUCCESS && config.Multiple.BreakOnSuccess {
      break
    }
  }

  var ipstr string
  if input.IP == nil {
    ipstr = ""
  } else {
    s := input.IP.String()
    ipstr = s
  }

  raw := Grab{IP: ipstr, Domain: input.Domain, Data: moduleResult}

  var outputData interface{} = raw

  if !includeDebugOutput() {
    // If the caller doesn't explicitly request debug data, strip it out.
    // Take advantage of the fact that we can skip the (expensive) call to
    // process if debug output is included (TODO: until Process does anything else)
    processor := output.Processor{Verbose: false}
    stripped, err := processor.Process(raw)
    if err != nil {
      log.Debugf("Error processing results: %v", err)
      stripped = raw
    }
    outputData = stripped
  }

  result, err := json.Marshal(outputData)
  if err != nil {
    log.Fatalf("unable to marshal data: %s", err)
  }

  return &result
}

type TargetConnection struct {
  Target *ScanTarget
  Conn *TLSConnection
}

// Process sets up an output encoder, input reader, and starts grab workers.
func Process(mon *Monitor) {
  workers := config.Senders
  numCoordinators := workers / 6

  processQueue := make(chan ScanTarget, workers*4)
  connectedQueue := make(chan TargetConnection, 1024 * 1024)
  outputQueue := make(chan *[]byte, 1024 * 1024)

  //Create wait groups
  var workerDone sync.WaitGroup
  var coordinatorDone sync.WaitGroup
  var outputDone sync.WaitGroup
  workerDone.Add(int(workers))
  coordinatorDone.Add(numCoordinators);
  outputDone.Add(1)

  //Start the coordinator
  for i := 0; i < numCoordinators; i++ {
    go func() {
      setAffinity(runtime.NumCPU() - (1 + i % 2))

      for _, scannerName := range orderedScanners {
        scanner := *scanners[scannerName]
        scanner.InitPerSender(0)
        for target := range processQueue {
          for run := uint(0); run < uint(config.ConnectionsPerHost); run++ {
            conn, err := scanner.Dial(target)
            if err != nil{
              mon.statusesChan <- moduleStatus{name: scannerName, st: statusFailure}
              //errString := err.Error()
              // TODO: Should write out a failure here
              continue
            } else {
              // TODO: should use actual deadline (scanner.config.BaseFlags.Timeout?)
              conn.Conn.SetDeadline(time.Now().Add(time.Second * 1))
              connectedQueue <- TargetConnection{ Target: &target, Conn: conn }
            }
          }
        }
      }

      coordinatorDone.Done()
    }()
  }

  //Start all the workers
  for i := 0; i < workers; i++ {
    go func(i int) {
      setAffinity(i % (runtime.NumCPU() - 1))
      moduleResult := make(map[string]*ScanResponse)

      for _, scannerName := range orderedScanners {
        scanner := *scanners[scannerName]
        scanner.InitPerSender(0)
        var target ScanTarget

        for tc := range connectedQueue {
          target = *tc.Target
          status, res, e := scanner.ScanConnection(tc, mon)
          // TODO: Stolen from scanner.go:RunScanner, should be worked into that
          var err *string
          if e == nil {
            mon.statusesChan <- moduleStatus{name: scannerName, st: statusSuccess}
            err = nil
          } else {
            mon.statusesChan <- moduleStatus{name: scannerName, st: statusFailure}
            errString := e.Error()
            err = &errString
          }

          // Todo: skipping a lot of steps here for multiple scans (see grabTarget)
          sr := ScanResponse{Result: &res, Protocol: scanner.Protocol(), Error: err, Timestamp: time.Now().Format(time.RFC3339), Status: status}
          moduleResult[scannerName] = &sr
        }

        raw := BuildGrabFromInputResponse(&target, moduleResult)
        out, err := EncodeGrab(raw, includeDebugOutput())
        if err != nil {
          log.Fatalf("unable to marshal data: %s", err)
        }

        outputQueue <- &out
      }
      workerDone.Done()
    }(i)
  }


  if err := config.inputTargets(processQueue); err != nil {
    log.Fatal(err)
  }
  close(processQueue)
  coordinatorDone.Wait()

  close(connectedQueue)
  workerDone.Wait()

  // Start the output encoder
  close(outputQueue)
  if err := config.outputResults(outputQueue); err != nil {
    log.Fatal(err)
  }
}

// EncodeGrab serializes a Grab to JSON, handling the debug fields if necessary.
func EncodeGrab(raw *Grab, includeDebug bool) ([]byte, error) {
  var outputData interface{}
  if includeDebug {
    outputData = raw
  } else {
    // If the caller doesn't explicitly request debug data, strip it out.
    // TODO: Migrate this to the ZMap fork of sheriff, once it's more
    // stable.
    processor := output.Processor{Verbose: false}
    stripped, err := processor.Process(raw)
    if err != nil {
      log.Debugf("Error processing results: %v", err)
      stripped = raw
    }
    outputData = stripped
  }
  return json.Marshal(outputData)
}

func BuildGrabFromInputResponse(t *ScanTarget, responses map[string]*ScanResponse) *Grab {
  var ipstr string

  if t.IP != nil {
    ipstr = t.IP.String()
  }
  return &Grab{
    IP:     ipstr,
    Domain: t.Domain,
    Data:   responses,
  }
}



