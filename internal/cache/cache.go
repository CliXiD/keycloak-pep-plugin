package cache

import (
	"sync"
	"time"
)

// Cache represents a simple in-memory cache with TTL
type Cache struct {
	items map[string]*item
	mutex sync.RWMutex
}

type item struct {
	value      interface{}
	expiration int64
}

// New creates a new cache instance
func New() *Cache {
	return &Cache{
		items: make(map[string]*item),
	}
}

// Set adds an item to the cache with TTL
func (c *Cache) Set(key string, value interface{}, ttl time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	expiration := time.Now().Add(ttl).UnixNano()
	c.items[key] = &item{
		value:      value,
		expiration: expiration,
	}
}

// Get retrieves an item from the cache
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	item, exists := c.items[key]
	if !exists {
		return nil, false
	}

	// Check if item has expired
	if time.Now().UnixNano() > item.expiration {
		c.mutex.RUnlock()
		c.mutex.Lock()
		delete(c.items, key)
		c.mutex.Unlock()
		c.mutex.RLock()
		return nil, false
	}

	return item.value, true
}

// Delete removes an item from the cache
func (c *Cache) Delete(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.items, key)
}

// Clear removes all items from the cache
func (c *Cache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.items = make(map[string]*item)
}

// Cleanup removes expired items from the cache
func (c *Cache) Cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now().UnixNano()
	for key, item := range c.items {
		if now > item.expiration {
			delete(c.items, key)
		}
	}
}