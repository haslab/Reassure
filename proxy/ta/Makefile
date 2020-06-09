#TA UUID
BINARY=98e095f5-fc26-4699-9460-26bb226d7a01

# Source the TA devkit
-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
clean:
	@echo 'NOTE: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit-mk not found, cannot clean TA'
	@echo 'NOTE: TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)'
endif
