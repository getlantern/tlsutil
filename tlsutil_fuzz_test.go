package tlsutil

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCorpus(t *testing.T) {
	t.Parallel()
	badRecords := make([][]byte, 0)

	f, err := os.Stat("./fuzz-data/corpus")
	if err != nil {
		// no corpus
		return
	}

	if !f.IsDir() {
		return
	}

	files, _ := ioutil.ReadDir("./fuzz-data/corpus")
	for _, f := range files {
		b, err := ioutil.ReadFile("./fuzz-data/corpus/" + f.Name())
		if err != nil {
			continue
		}
		badRecords = append(badRecords, b)
	}

	for i, r := range badRecords {
		t.Logf("parsing record %d", i)
		assert.NotPanics(t, func() {
			ValidateClientHello(r)
		})
	}

}
