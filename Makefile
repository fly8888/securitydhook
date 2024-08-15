export TARGET = iphone:latest:10.0

export ARCHS = arm64 arm64e
export GO_EASY_ON_ME = 1
export DEBUG = 0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = securityhook

securityhook_FILES = $(wildcard ./*.xm)

ADDITIONAL_OBJCFLAGS =-fno-objc-arc 

securityhook_FRAMEWORKS = UIKit Foundation 



include $(THEOS_MAKE_PATH)/tweak.mk



after-install::
	install.exec "killall -9 securityd"
