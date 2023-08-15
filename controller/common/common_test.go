package common

import (
	"os"
	"testing"

	"github.com/neuvector/neuvector/share/utils"
	"github.com/stretchr/testify/assert"
)

func TestDefaultPasswordHelper(t *testing.T) {
	os.Setenv("DEFAULT_PASSWORD", "password")
	assert.True(t, IsDefaultAdminPass("password"))
	assert.True(t, IsDefaultAdminPass("admin"))
	assert.False(t, IsDefaultAdminPass("12345"))
	assert.True(t, IsDefaultAdminPassHash(utils.HashPassword("password")))
	assert.True(t, IsDefaultAdminPassHash(utils.HashPassword("admin")))
	assert.False(t, IsDefaultAdminPassHash(utils.HashPassword("12345")))

	os.Unsetenv("DEFAULT_PASSWORD")
	assert.False(t, IsDefaultAdminPass("password"))
	assert.True(t, IsDefaultAdminPass("admin"))
	assert.False(t, IsDefaultAdminPass("12345"))
	assert.False(t, IsDefaultAdminPassHash(utils.HashPassword("password")))
	assert.True(t, IsDefaultAdminPassHash(utils.HashPassword("admin")))
	assert.False(t, IsDefaultAdminPassHash(utils.HashPassword("12345")))

	os.Setenv("DEFAULT_PASSWORD", "")
	assert.False(t, IsDefaultAdminPass("password"))
	assert.True(t, IsDefaultAdminPass("admin"))
	assert.False(t, IsDefaultAdminPass("12345"))
	assert.False(t, IsDefaultAdminPassHash(utils.HashPassword("password")))
	assert.True(t, IsDefaultAdminPassHash(utils.HashPassword("admin")))
	assert.False(t, IsDefaultAdminPassHash(utils.HashPassword("12345")))
}
