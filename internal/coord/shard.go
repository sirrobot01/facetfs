package coord

import "hash/fnv"

func shardIndex(key string) uint32 {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(key))
	return hash.Sum32() % shardCount
}
