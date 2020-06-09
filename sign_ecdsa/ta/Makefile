#TA UUID
BINARY=020e5b82-2862-4c49-8220-b2ad1a374eea

# Source the TA devkit
-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
clean:
	@echo 'NOTE: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit-mk not found, cannot clean TA'
	@echo 'NOTE: TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)'
endif
