package gommap_test

import (
	"fmt"
	"github.com/heyvito/gommap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path"
	"syscall"
	"testing"
)

var testData = []byte("0123456789ABCDEF")

func Example() {
	filePath := "/tmp/mapped_file"
	file, err := os.Create(filePath)
	if err != nil {
		panic("Creating temporary file failed: " + err.Error())
	}
	_, err = file.Write([]byte("0123456789ABCDEF"))
	if err != nil {
		panic("Writing to temporary file failed: " + err.Error())
	}

	mmap, err := gommap.Map(file.Fd(), gommap.PROT_READ|gommap.PROT_WRITE, gommap.MAP_SHARED)
	if err != nil {
		panic("Initializing memory mapping failed: " + err.Error())
	}

	defer mmap.UnsafeUnmap()

	mmap[9] = 'X'
	err = mmap.Sync(gommap.MS_SYNC)
	if err != nil {
		panic("mmap sync failed: " + err.Error())
	}

	fileData, err := os.ReadFile(filePath)
	if err != nil {
		panic("Reading temporary file failed: " + err.Error())
	}
	fmt.Println(string(fileData))
	// Output: 012345678XABCDEF
}

func setup(t *testing.T) *os.File {
	t.Helper()
	testPath := path.Join(t.TempDir(), "test.txt")
	file, err := os.Create(testPath)
	require.NoError(t, err)
	_, err = file.Write(testData)
	require.NoError(t, err)
	return file
}

func TestUnsafeUnmap(t *testing.T) {
	f := setup(t)
	mmap, err := gommap.Map(f.Fd(), gommap.PROT_READ|gommap.PROT_WRITE, gommap.MAP_SHARED)
	require.NoError(t, err)
	require.NoError(t, mmap.UnsafeUnmap())
}

func TestReadWrite(t *testing.T) {
	f := setup(t)
	mmap, err := gommap.Map(f.Fd(), gommap.PROT_READ|gommap.PROT_WRITE, gommap.MAP_SHARED)
	require.NoError(t, err)
	defer mmap.UnsafeUnmap()
	assert.Equal(t, []byte(mmap), testData)

	mmap[9] = 'X'
	require.NoError(t, mmap.Sync(gommap.MS_SYNC))

	fileData, err := os.ReadFile(f.Name())
	require.NoError(t, err)
	assert.Equal(t, fileData, []byte("012345678XABCDEF"))
}

func TestSliceMethods(t *testing.T) {
	f := setup(t)
	mmap, err := gommap.Map(f.Fd(), gommap.PROT_READ|gommap.PROT_WRITE, gommap.MAP_SHARED)
	require.NoError(t, err)
	defer mmap.UnsafeUnmap()
	assert.Equal(t, []byte(mmap), testData)

	mmap[9] = 'X'

	// This may fail on different OSes, so let's not assert for whether it
	// returns an error or not.
	_ = mmap[7:10].Sync(gommap.MS_SYNC)

	fileData, err := os.ReadFile(f.Name())
	require.NoError(t, err)
	assert.Equal(t, fileData, []byte("012345678XABCDEF"))
}

func TestProtFlagsAndErr(t *testing.T) {
	f := setup(t)
	testPath := f.Name()
	err := f.Close()
	require.NoError(t, err)
	file, err := os.Open(testPath)
	require.NoError(t, err)
	f = file
	_, err = gommap.Map(f.Fd(), gommap.PROT_READ|gommap.PROT_WRITE, gommap.MAP_SHARED)
	// For this to happen, both the error and the protection flag must work.
	assert.Equal(t, syscall.EACCES, err)
}

func TestFlags(t *testing.T) {
	f := setup(t)
	mmap, err := gommap.Map(f.Fd(), gommap.PROT_READ|gommap.PROT_WRITE, gommap.MAP_PRIVATE)
	require.NoError(t, err)
	defer mmap.UnsafeUnmap()

	mmap[9] = 'X'
	require.NoError(t, mmap.Sync(gommap.MS_SYNC))

	fileData, err := os.ReadFile(f.Name())
	require.NoError(t, err)
	// Shouldn't have written, since the map is private.
	assert.Equal(t, fileData, []byte("0123456789ABCDEF"))
}

func TestAdvise(t *testing.T) {
	f := setup(t)
	mmap, err := gommap.Map(f.Fd(), gommap.PROT_READ|gommap.PROT_WRITE, gommap.MAP_PRIVATE)
	require.NoError(t, err)
	defer mmap.UnsafeUnmap()

	// A bit tricky to blackbox-test these.
	err = mmap.Advise(gommap.MADV_RANDOM)
	require.NoError(t, err)

	err = mmap.Advise(9999)
	assert.ErrorContains(t, err, "invalid argument")
}

func TestProtect(t *testing.T) {
	f := setup(t)
	mmap, err := gommap.Map(f.Fd(), gommap.PROT_READ, gommap.MAP_SHARED)
	require.NoError(t, err)
	defer mmap.UnsafeUnmap()
	assert.Equal(t, []byte(mmap), testData)

	err = mmap.Protect(gommap.PROT_READ | gommap.PROT_WRITE)
	assert.NoError(t, err)

	// If this operation doesn't blow up tests, the call above worked.
	mmap[9] = 'X'
}

func TestLock(t *testing.T) {
	f := setup(t)
	mmap, err := gommap.Map(f.Fd(), gommap.PROT_READ|gommap.PROT_WRITE, gommap.MAP_PRIVATE)
	require.NoError(t, err)
	defer mmap.UnsafeUnmap()

	// A bit tricky to blackbox-test these.
	err = mmap.Lock()
	require.NoError(t, err)

	err = mmap.Lock()
	require.NoError(t, err)

	err = mmap.Unlock()
	require.NoError(t, err)

	err = mmap.Unlock()
	require.NoError(t, err)
}

func TestIsResidentUnderOnePage(t *testing.T) {
	f := setup(t)
	mmap, err := gommap.Map(f.Fd(), gommap.PROT_READ|gommap.PROT_WRITE, gommap.MAP_PRIVATE)
	require.NoError(t, err)
	defer mmap.UnsafeUnmap()

	mapped, err := mmap.IsResident()
	require.NoError(t, err)
	require.Equal(t, mapped, []bool{true})
}

func TestIsResidentTwoPages(t *testing.T) {
	testPath := path.Join(t.TempDir(), "test.txt")
	file, err := os.Create(testPath)
	require.NoError(t, err)
	defer file.Close()

	_, err = file.Seek(int64(os.Getpagesize()*2-1), 0)
	require.NoError(t, err)
	_, err = file.Write([]byte{'x'})
	require.NoError(t, err)

	mmap, err := gommap.Map(file.Fd(), gommap.PROT_READ|gommap.PROT_WRITE, gommap.MAP_PRIVATE)
	require.NoError(t, err)
	defer mmap.UnsafeUnmap()

	// Not entirely a stable test, but should usually work.

	mmap[len(mmap)-1] = 'x'

	mapped, err := mmap.IsResident()
	require.NoError(t, err)
	assert.Equal(t, mapped, []bool{false, true})

	mmap[0] = 'x'

	mapped, err = mmap.IsResident()
	require.NoError(t, err)
	assert.Equal(t, mapped, []bool{true, true})
}
