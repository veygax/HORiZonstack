

















NDK ?= /home/elambert/android-ndk-cache/android-ndk-r29
API ?= 30
CC := $(NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android$(API)-clang
CFLAGS := -O2 -fPIE -pie -Wall \
	-Wno-int-to-pointer-cast -Wno-pointer-to-int-cast -Wno-format \
	-Wno-unused  
TARGET := horizonstack

all: $(TARGET)

$(TARGET): horizonstack.c tables.c Makefile
	$(CC) $(CFLAGS) -o $@ horizonstack.c

push: $(TARGET)
	adb push $(TARGET) /data/local/tmp/$(TARGET)
	adb shell chmod 755 /data/local/tmp/$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all push clean
