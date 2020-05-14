package main

import (
	"fmt"
	"sync"
	"sort"
	"log"
	"math/rand"
	"time"
	"hash/fnv"
	"github.com/gin-gonic/gin"
	"net"
)

const DEFAULT_WEIGHT=10
const SEED = "seed"
//serverpool comntains list of all proxyholders/backends
type ServerPool struct {
	ProxyHolders	[]*ProxyHolder
	Totals 			[]int
	Mux				sync.RWMutex
	Max				int
}


func NewServerPool() *ServerPool {
	return new(ServerPool)
}

func hash(s string) int64 {
        h := fnv.New32a()
        h.Write([]byte(s))
        return int64(h.Sum32())
}

func GetSeed(c *gin.Context) int64 {
	val, ok := c.Get(SEED)
	if ok {
		return val.(int64)
	}
	clientname := c.ClientIP()
	if c.IsWebsocket() {
		// only gets a new index hourly per hostname
		return (time.Now().Unix()/3600)*hash(clientname)
	} else {
		return time.Now().UnixNano()*hash(clientname)
	}
}

//save seed in the context for reuse
func SetSeed(c *gin.Context) {
	c.Set(SEED, GetSeed(c))
}

func (s *ServerPool) IsEmpty() bool {
	s.Mux.RLock()
	isempty := len(s.ProxyHolders) == 0
	s.Mux.RUnlock()
	return isempty
}

func (s *ServerPool) Add(proxyholder *ProxyHolder) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if !*lbEnabled {
		s.ProxyHolders = make([]*ProxyHolder,0)
		s.ProxyHolders = append(s.ProxyHolders, proxyholder)
		return
	}
	// no of servers in pool will be constant only
	s.ProxyHolders = append(s.ProxyHolders, proxyholder)
	sort.Slice(s.ProxyHolders, func(i, j int) bool {
		return s.ProxyHolders[i].Weight < s.ProxyHolders[j].Weight
	})
	s.Totals = append(s.Totals, 0)
	runningTotal := 0
	for i, p := range s.ProxyHolders {
		runningTotal += int(p.Weight)
		s.Totals[i] = runningTotal
	}

	s.Max = runningTotal
}

func (s *ServerPool) Delete(proxyholder *ProxyHolder) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if !*lbEnabled {
		if len(s.ProxyHolders) > 0 {
			s.ProxyHolders = make([]*ProxyHolder,0)
		}
		return
	}
	// no of servers in pool will be constant only
	index := -1
	for i, ph := range s.ProxyHolders {
		if proxyholder.ProxyHost == ph.ProxyHost && proxyholder.ProxyTo == ph.ProxyTo {
			index = i
			break
		}
	}
	if index == -1 {
		log.Println("Error deleting proxy : ", proxyholder.ProxyHost, proxyholder.ProxyTo)
		return
	}
	//size reduction
	s.ProxyHolders = append(s.ProxyHolders[:index], s.ProxyHolders[index+1:]...)
	s.Totals = make([]int, len(s.ProxyHolders))
	runningTotal := 0
	for i, p := range s.ProxyHolders {
		runningTotal += int(p.Weight)
		s.Totals[i] = runningTotal
	}

	s.Max = runningTotal
}

// select one of the proxyholders for routing
func (s *ServerPool) Select(seed int64) (ph *ProxyHolder, ok bool) {
	s.Mux.RLock()
	defer s.Mux.RUnlock()
	if !*lbEnabled || seed == -1 {
		if len(s.ProxyHolders) > 0 {
			ph = s.ProxyHolders[0]
			ok = true
		}
		return ph, ok
	}
	
	
	rand.Seed(seed)
	
	r := rand.Intn(s.Max) + 1
	i := sort.SearchInts(s.Totals, r)
	if i < len(s.ProxyHolders) {
		ph = s.ProxyHolders[i]
		ok = true
	}
	return ph, ok
}

func (s *ServerPool) ToString() string {
	str := ""
	s.Mux.RLock()
	defer s.Mux.RUnlock()
	for _, ph := range s.ProxyHolders {
		str +=fmt.Sprint(ph.ProxyHost," : ",*ph)+"\n"
	}
	return str
}


// httplistenermap
type HTTPListenerMap struct {
	sync.Map
}

// store
func (m *HTTPListenerMap) AddtoServerPool(hostname string, proxyholder *ProxyHolder) {
	var serverpool *ServerPool
	spool, ok := m.Load(hostname)
	if !ok || spool == nil {
		serverpool = NewServerPool()
		m.Store(hostname, serverpool)
	} else {
		serverpool = spool.(*ServerPool)
	}
	proxyholder.Weight = DEFAULT_WEIGHT
	clientname, _, _ := net.SplitHostPort(proxyholder.SSHConn.SSHConn.RemoteAddr().String())
	if clientname == "localhost" || clientname == "127.0.0.1" {
		proxyholder.Weight = 1 // less weight for localhost
	}
	serverpool.Add(proxyholder)
	log.Println(" client added to serverpool: ",clientname, proxyholder)
}

// store
func (m *HTTPListenerMap) DeleteFromServerPool(hostname string, proxyholder *ProxyHolder) {
	spool, ok := m.Load(hostname)
	if !ok || spool == nil {
		return
	}
	serverpool := spool.(*ServerPool)
	serverpool.Delete(proxyholder)
	if (serverpool.IsEmpty()) {
		m.Delete(hostname) // delete empty host table
	}
}

// store
func (m *HTTPListenerMap) LoadFromServerPool(hostname string, c *gin.Context) (ph *ProxyHolder, ok bool) {
	spool, ok := m.Load(hostname)
	if !ok || spool==nil {
		return ph, false
	}
	serverpool := spool.(*ServerPool)
	return serverpool.Select(GetSeed(c))
}
