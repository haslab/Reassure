#TA UUID
BINARY=1d7cc9bf-e2ed-48de-8a8d-d591ecdfecac

# Source the TA devkit
-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
clean:
	@echo 'NOTE: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit-mk not found, cannot clean TA'
	@echo 'NOTE: TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)'
endif
