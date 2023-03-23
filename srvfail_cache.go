package resolve

import (
	"sync"
)

var srvFailMap map[string]bool = make(map[string]bool)
var srvFailMapMutex sync.RWMutex

func checkForDomainDNSOk(name string) bool {
	srvFailMapMutex.RLock()
	_, ok := srvFailMap[name]
	srvFailMapMutex.RUnlock()
	return !ok
}

func registerSrvFail(name string) {
	srvFailMapMutex.Lock()
	srvFailMap[name] = true
	srvFailMapMutex.Unlock()
}
