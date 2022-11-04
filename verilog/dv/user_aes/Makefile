
# // //////////////////////////////////////////////////////////////////////////
#------------------------------------------------------------------------------
# Makefile for Synthesis
#------------------------------------------------------------------------------

# Paths
export ROOT_DIR := $(shell pwd)

##########################################################################
#
# Test Bench Sources
#
##########################################################################
TB_SRC_DIR=./
_TB_=		$(TB_SRC_DIR)/tb_top.v	

##########################################################################
#
# DUT Sources
#
##########################################################################
DUT_SRC_DIR=../../rtl
_TARGETS_=	$(DUT_SRC_DIR)/aes128/core/aes_sbox.sv			    \
		    $(DUT_SRC_DIR)/aes128/core/aes_rcon.sv			    \
		    $(DUT_SRC_DIR)/aes128/core/aes_key_expand_128.sv	\
		    $(DUT_SRC_DIR)/aes128/core/aes_cipher_top.sv		\
		    $(DUT_SRC_DIR)/aes128/core/aes_inv_sbox.sv			\
		    $(DUT_SRC_DIR)/aes128/core/aes_inv_cipher_top.sv    \
		    $(DUT_SRC_DIR)/aes128/top/aes_top.sv                \
		    $(DUT_SRC_DIR)/aes128/top/aes_reg.sv                \
		    $(DUT_SRC_DIR)/lib/registers.v                      \
		    $(DUT_SRC_DIR)/lib/reset_sync.sv                    \
		    $(DUT_SRC_DIR)/lib/clk_skew_adjust.gv               \
		    $(DUT_SRC_DIR)/lib/ctech_cells.sv


### To Enable IVERILOG FST DUMP
export IVERILOG_DUMPER = fst

# Targets
.PHONY: clean rtl gate help

default: clean rtl

rtl: clean  
	iverilog -g2012  -D SPEEDSIM  -DFUNCTIONAL -DSIM -DWFDUMP -I ./$(DUT_SRC_DIR)/ -I ./$(TB_SRC_DIR)/ -I $(PDK_ROOT)/sky130A    $(_TB_) $(_TARGETS_)  -o tb_top.vvp
	vvp tb_top.vvp

gate: clean  
	iverilog -g2012  -D GL -D SPEEDSIM  -DFUNCTIONAL -DSIM -DWFDUMP -I ./$(DUT_SRC_DIR)/ -I ./$(TB_SRC_DIR)/ -I $(PDK_ROOT)/sky130A  $(_TB_) $(_TARGETS_) -o tb_top.vvp
	vvp tb_top.vvp

help:
	@echo "To run RTL  simulation: make rtl"
	@echo "To run Gate simulation: make gate"



clean:
	$(RM) -R *.vvp
	$(RM) -R *.vcd
	$(RM) -R *.fst
