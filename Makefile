buildflags = -ldflags="-s -w" -i
binname = gosum
distr:
	go build ${buildflags} -o bin/${binname}.exe
	cp README.md README.txt
	zip ${binname} -j bin/${binname}.exe README.txt
	rm README.txt

mkbin:
	mkdir bin
