hash=`git rev-parse --short HEAD`
rc=`date "+%Y-%m-%d_%H:%M:%S"`
target=ipreset
go build -ldflags "-s -w -X main.GitHash=${hash} -X main.CompileTime=${rc}" -o ${target} main.go
chmod a+x ${target}
