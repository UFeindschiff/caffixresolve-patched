package resolve

import (
	"sync"
	"strings"
)

var srvFailMap map[string]bool = make(map[string]bool)
var srvFailMapMutex sync.RWMutex

func checkForDomainDNSOk(name string) bool {
	srvFailMapMutex.RLock()
	_, ok := srvFailMap[name]
	srvFailMapMutex.RUnlock()
	return !ok
}

func checkForDomainDNSOkSuffix(name string) bool {
	srvFailMapMutex.RLock()
	defer srvFailMapMutex.RUnlock()
	for key, _ := range srvFailMap {
		if strings.HasSuffix(name, key) {
			return false
		}
	}
	return true
}

func registerSrvFail(name string) {
	srvFailMapMutex.Lock()
	srvFailMap[name] = true
	srvFailMapMutex.Unlock()
}
