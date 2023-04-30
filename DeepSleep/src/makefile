build = ../../build
make:
	nasm -f win64 adjuststack.asm -o $(build)/adjuststack.o
	nasm -f win64 asmStubs.nasm -o $(build)/asmStubs.o 
	x86_64-w64-mingw32-gcc Cleanup.cpp  -Wall -m64 -masm=intel -ffunction-sections -fno-stack-protector -fno-asynchronous-unwind-tables -nostdlib -fno-ident -g0 -O2 -c -o $(build)/Cleanup.o -Wl,--no-seh
	x86_64-w64-mingw32-gcc ApiResolve.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -g0 -O2 -c -o $(build)/ApiResolve.o -Wl,--no-seh
	x86_64-w64-mingw32-gcc Main.c -Wall -m64 -masm=intel -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -g0 -O2 -c -o $(build)/Main.o -Wl,--no-seh
	x86_64-w64-mingw32-ld -s $(build)/adjuststack.o $(build)/asmStubs.o $(build)/ApiResolve.o $(build)/Cleanup.o $(build)/Main.o -o $(build)/DeepSleep.exe

	objcopy -O binary DeepSleep.exe $(build)/DeepSleep.bin
