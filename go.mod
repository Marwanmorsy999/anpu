module github.com/anpu-project/anpu

go 1.22

require (
	github.com/mattn/go-sqlite3 v1.14.22
	github.com/spf13/cobra v1.8.1
)

require github.com/spf13/pflag v1.0.5 // indirect

require github.com/inconshreveable/mousetrap v1.1.0 // indirect

replace github.com/spf13/cobra => ./third_party/cobra

replace github.com/spf13/pflag => ./third_party/pflag

replace github.com/mattn/go-sqlite3 => ./third_party/go-sqlite3

replace github.com/inconshreveable/mousetrap => ./third_party/mousetrap

require gopkg.in/yaml.v3 v3.0.1
replace gopkg.in/yaml.v3 => ./third_party/yaml
