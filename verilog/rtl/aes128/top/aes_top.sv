/*********************************************************************************
 SPDX-FileCopyrightText: 2021 , Dinesh Annayya                          
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 SPDX-License-Identifier: Apache-2.0
 SPDX-FileContributor: Created by Dinesh Annayya <dinesh.annayya@gmail.com>

***********************************************************************************/
/**********************************************************************************
                                                              
                   AES  Top Module                                             
                                                              
  Description                                                 
     AES Top module includes 128 bit aes_cipher &  aes_inv_cipher                                           
     
  To Do:                                                      
    1. Integration 192/256 AES
                                                              
  Author(s):                                                  
      - Dinesh Annayya, dinesh.annayya@gmail.com                 
                                                              
  Revision :                                                  
     0.0  - Oct 15, 2022 
            Initial Version picked from https://opencores.org/ocsvn/aes_core                                    
     0.1  - Nov 3, 2022
            Following changes are done
            1. Wishbone register interface added
            2. To reduce the design area of the aes_cipher and aes_inv_cipher
               A. aes_sbox used sequentially for 16 cycle for text compuation 
               B. 4 cycle for next round key computation
           
                                                              
************************************************************************************/

module aes_top #( parameter WB_WIDTH = 32) (
`ifdef USE_POWER_PINS
    input logic                          vccd1,    // User area 1 1.8V supply
    input logic                          vssd1,    // User area 1 digital ground
`endif

    input  logic                         mclk,
    input  logic                         rst_n,

    input  logic   [3:0]                 cfg_cska,
    input  logic                         wbd_clk_int,
    output logic                         wbd_clk_out,

    input  logic                         wbd_stb_i, // strobe/request
    input  logic   [6:0]                 wbd_adr_i, // address
    input  logic                         wbd_we_i,  // write
    input  logic   [WB_WIDTH-1:0]        wbd_dat_i, // data output
    input  logic   [3:0]                 wbd_sel_i, // byte enable
    output logic   [WB_WIDTH-1:0]        wbd_dat_o, // data input
    output logic                         wbd_ack_o  // acknowlegement

);


logic [31:0]  reg_rdata_enc;
logic [31:0]  reg_rdata_decr;
logic         reg_enc;
logic         reg_decr;


// Encription local variable
logic         cfg_enc_ld;                   
logic         enc_done ;                    
logic [127:0] cfg_enc_key;
logic [127:0] cfg_enc_text_in;
logic [127:0] enc_text_out;

// Decryption local variable
logic         cfg_decr_kld;                
logic         decr_done   ;                
logic [127:0] cfg_decr_key;                
logic [127:0] cfg_decr_text_in;            
logic [127:0] decr_text_out;               


assign reg_enc  = wbd_stb_i & (wbd_adr_i[6] == 1'b0);
assign reg_decr = wbd_stb_i & (wbd_adr_i[6] == 1'b1);

assign wbd_dat_o = (reg_enc) ? reg_rdata_enc : (reg_decr) ? reg_rdata_decr : 'h0;
assign wbd_ack_o = (reg_enc) ? reg_ack_enc   : (reg_decr) ? reg_ack_decr   : 'h0;

//###################################
// Clock Skey for WB clock
//###################################
clk_skew_adjust u_skew
       (
`ifdef USE_POWER_PINS
           .vccd1      (vccd1                      ),// User area 1 1.8V supply
           .vssd1      (vssd1                      ),// User area 1 digital ground
`endif
	       .clk_in     (wbd_clk_int                ), 
	       .sel        (cfg_cska                   ), 
	       .clk_out    (wbd_clk_out                ) 
       );

//###################################
// Application Reset Synchronization
//###################################
reset_sync  u_app_rst (
	         .scan_mode  (1'b0        ),
             .dclk       (mclk        ), // Destination clock domain
	         .arst_n     (rst_n       ), // active low async reset
             .srst_n     (rst_ss_n    )
          );


//###################################
// Encription Register
//###################################
aes_reg u_enc_reg(
        .mclk                           (mclk                         ),
        .rst_n                          (rst_ss_n                     ),

        .reg_cs                         (reg_enc                      ), // strobe/request
        .reg_addr                       (wbd_adr_i[5:2]               ), // address
        .reg_wr                         (wbd_we_i                     ), // write
        .reg_wdata                      (wbd_dat_i                    ), // data output
        .reg_be                         (wbd_sel_i                    ), // byte enable
        .reg_rdata                      (reg_rdata_enc                ), // data input
        .reg_ack                        (reg_ack_enc                  ), // acknowlegement

      // Encription Reg Interface
        .cfg_aes_ld                     (cfg_enc_ld                   ),
        .aes_done                       (enc_done                     ),
        .cfg_key                        (cfg_enc_key                  ),
        .cfg_text_in                    (cfg_enc_text_in              ),
        .text_out                       (enc_text_out                 )

      );


//###################################
// Encription core
//###################################
aes_cipher_top  u_cipher (
       .clk                             (mclk                        ), 
       .rstn                            (rst_ss_n                    ), 
       .ld                              (cfg_enc_ld                  ), 
       .done                            (enc_done                    ), 
       .key                             (cfg_enc_key                 ), 
       .text_in                         (cfg_enc_text_in             ), 
       .text_out                        (enc_text_out                )
     );

//###################################
// Decryption Register
//###################################
aes_reg u_decr_reg(
        .mclk                           (mclk                         ),
        .rst_n                          (rst_ss_n                     ),

        .reg_cs                         (reg_decr                     ), // strobe/request
        .reg_addr                       (wbd_adr_i[5:2]               ), // address
        .reg_wr                         (wbd_we_i                     ), // write
        .reg_wdata                      (wbd_dat_i                    ), // data output
        .reg_be                         (wbd_sel_i                    ), // byte enable
        .reg_rdata                      (reg_rdata_decr               ), // data input
        .reg_ack                        (reg_ack_decr                 ), // acknowlegement

      // Decription Reg Interface
        .cfg_aes_ld                     (cfg_decr_kld                 ),
        .aes_done                       (decr_done                    ),
        .cfg_key                        (cfg_decr_key                 ),
        .cfg_text_in                    (cfg_decr_text_in             ),
        .text_out                       (decr_text_out                )

      );

//###################################
// Decryption Core
//###################################
aes_inv_cipher_top u_icipher (
       .clk                            (mclk                         ), 
       .rstn                           (rst_ss_n                     ), 
       .kld                            (cfg_decr_kld                 ), 
       .ld                             (decr_kdone                   ), 
       .kdone                          (decr_kdone                   ),
       .done                           (decr_done                    ), 
       .key                            (cfg_decr_key                 ), 
       .text_in                        (cfg_decr_text_in             ), 
       .text_out                       (decr_text_out                ) 
     );

endmodule


