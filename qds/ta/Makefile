#TA UUID
BINARY=ced14a59-a522-4088-ba4f-bd4be1b3c06d

# TP TA
CFG_TP_TA=y
TP_KEY_TYPE=rsa

# Source the TA devkit
-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
clean:
	@echo 'NOTE: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit-mk not found, cannot clean TA'
	@echo 'NOTE: TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)'
endif
