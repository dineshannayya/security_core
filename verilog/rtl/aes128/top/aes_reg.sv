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
                                                              
                   AES Register Interface
                                                              
  Description:                                                 
     
  To Do:                                                      
                                                              
  Author(s):                                                  
      - Dinesh Annayya, dinesh.annayya@gmail.com                 
                                                              
  Revision :                                                  
     0.0  - Nov 3, 2022
            Initial Version
           
                                                              
************************************************************************************/

module aes_reg (
        input  logic           mclk                    ,
        input  logic           rst_n                   ,

        input  logic           reg_cs                  , // strobe/request
        input  logic [3:0]     reg_addr                , // address
        input  logic           reg_wr                  , // write
        input  logic [31:0]    reg_wdata               , // data output
        input  logic [3:0]     reg_be                  , // byte enable
        output logic [31:0]    reg_rdata               , // data input
        output logic           reg_ack                 , // acknowlegement

      // Encription Reg Interface
        output  logic          cfg_aes_ld              ,
        input   logic          aes_done                ,
        output  logic [127:0]  cfg_key                 ,
        output  logic [127:0]  cfg_text_in             ,
        input   logic [127:0]  text_out                


      );

//-----------------------------------------------------------------------
// Internal Wire Declarations
//-----------------------------------------------------------------------

logic          sw_rd_en        ;
logic          sw_wr_en        ;
logic [3:0]    sw_addr         ; 
logic [31:0]   sw_reg_wdata    ;
logic [3:0]    sw_be           ;

logic [31:0]   reg_out         ;
logic [31:0]   reg_0           ; 
logic [31:0]   reg_1           ; 
logic [31:0]   reg_2           ; 
logic [31:0]   reg_3           ; 
logic [31:0]   reg_4           ; 
logic [31:0]   reg_5           ; 
logic [31:0]   reg_6           ; 
logic [31:0]   reg_7           ; 
logic [31:0]   reg_8           ; 
logic [31:0]   reg_9           ; 
logic [31:0]   reg_10          ; 
logic [31:0]   reg_11          ; 
logic [31:0]   reg_12          ; 
logic          cfg_aes_req     ;
logic          cfg_aes_req_l   ;


assign       sw_addr       = reg_addr;
assign       sw_rd_en      = reg_cs & !reg_wr;
assign       sw_wr_en      = reg_cs & reg_wr;
assign       sw_be         = reg_be;
assign       sw_reg_wdata  = reg_wdata;

//-----------------------------------------------------------------------
// register read enable and write enable decoding logic
//-----------------------------------------------------------------------
wire   sw_wr_en_0 = sw_wr_en  & (sw_addr == 4'h0);
wire   sw_wr_en_1 = sw_wr_en  & (sw_addr == 4'h1);
wire   sw_wr_en_2 = sw_wr_en  & (sw_addr == 4'h2);
wire   sw_wr_en_3 = sw_wr_en  & (sw_addr == 4'h3);
wire   sw_wr_en_4 = sw_wr_en  & (sw_addr == 4'h4);
wire   sw_wr_en_5 = sw_wr_en  & (sw_addr == 4'h5);
wire   sw_wr_en_6 = sw_wr_en  & (sw_addr == 4'h6);
wire   sw_wr_en_7 = sw_wr_en  & (sw_addr == 4'h7);
wire   sw_wr_en_8 = sw_wr_en  & (sw_addr == 4'h8);

wire   sw_rd_en_0 = sw_rd_en  & (sw_addr == 4'h0);
wire   sw_rd_en_1 = sw_rd_en  & (sw_addr == 4'h1);
wire   sw_rd_en_2 = sw_rd_en  & (sw_addr == 4'h2);
wire   sw_rd_en_3 = sw_rd_en  & (sw_addr == 4'h3);
wire   sw_rd_en_4 = sw_rd_en  & (sw_addr == 4'h4);
wire   sw_rd_en_5 = sw_rd_en  & (sw_addr == 4'h5);
wire   sw_rd_en_6 = sw_rd_en  & (sw_addr == 4'h6);
wire   sw_rd_en_7 = sw_rd_en  & (sw_addr == 4'h7);
wire   sw_rd_en_8 = sw_rd_en  & (sw_addr == 4'h8);


always @ (posedge mclk or negedge rst_n)
begin : preg_out_Seq
   if (rst_n == 1'b0) begin
      reg_rdata  <= 'h0;
      reg_ack    <= 1'b0;
   end else if (reg_cs && !reg_ack) begin
      reg_rdata  <= reg_out;
      reg_ack    <= 1'b1;
   end else begin
      reg_ack    <= 1'b0;
   end
end

//-----------------------------------------------------------------------
// Register Read Path Multiplexer instantiation
//-----------------------------------------------------------------------

always_comb
begin 
  reg_out [31:0] = 32'h0;

  case (sw_addr [3:0])
    4'b0000    : reg_out [31:0] = {31'h0,cfg_aes_req};     
    4'b0001    : reg_out [31:0] = reg_1  [31:0];    
    4'b0010    : reg_out [31:0] = reg_2  [31:0];     
    4'b0011    : reg_out [31:0] = reg_3  [31:0];    
    4'b0100    : reg_out [31:0] = reg_4  [31:0];    
    4'b0101    : reg_out [31:0] = reg_5  [31:0];    
    4'b0110    : reg_out [31:0] = reg_6  [31:0];    
    4'b0111    : reg_out [31:0] = reg_7  [31:0];    
    4'b1000    : reg_out [31:0] = reg_8  [31:0];    
    4'b1001    : reg_out [31:0] = reg_9  [31:0];    
    4'b1010    : reg_out [31:0] = reg_10 [31:0];    
    4'b1011    : reg_out [31:0] = reg_11 [31:0];    
    4'b1100    : reg_out [31:0] = reg_12 [31:0];    
    default    : reg_out [31:0] = 32'h0;
  endcase
end


assign cfg_aes_ld = (cfg_aes_req && !cfg_aes_req_l);

always @ (posedge mclk or negedge rst_n)
begin
   if (rst_n == 1'b0) begin
     cfg_aes_req_l <= 1'b0;
   end else begin
      cfg_aes_req_l <= cfg_aes_req;
   end
end
assign reg_0[0]                     = cfg_aes_req;


assign cfg_key                      = {reg_4,reg_3,reg_2,reg_1};
assign cfg_text_in                  = {reg_8,reg_7,reg_6,reg_5};
assign {reg_12,reg_11,reg_10,reg_9} = text_out;

//  Register-0 
req_register #(0  ) u_ctrl (
	      .cpu_we       ({sw_wr_en_0 & 
                             sw_be[0]   }),		 
	      .cpu_req      (sw_reg_wdata[0] ),
	      .hware_ack    (aes_done        ),
	      .reset_n      (rst_n           ),
	      .clk          (mclk            ),
	      
	      //List of Outs
	      .data_out     (cfg_aes_req     )
          );
 

//  Register-1 
gen_32b_reg  #(32'h0) u_reg_1	(
	      //List of Inputs
	      .reset_n    (rst_n         ),
	      .clk        (mclk          ),
	      .cs         (sw_wr_en_1    ),
	      .we         (sw_be         ),		 
	      .data_in    (sw_reg_wdata  ),
	      
	      //List of Outs
	      .data_out   (reg_1         )
	      );

//  Register-2 
gen_32b_reg  #(32'h0) u_reg_2	(
	      //List of Inputs
	      .reset_n    (rst_n         ),
	      .clk        (mclk          ),
	      .cs         (sw_wr_en_2    ),
	      .we         (sw_be         ),		 
	      .data_in    (sw_reg_wdata  ),
	      
	      //List of Outs
	      .data_out   (reg_2         )
	      );

//  Register-3 
gen_32b_reg  #(32'h0) u_reg_3	(
	      //List of Inputs
	      .reset_n    (rst_n         ),
	      .clk        (mclk          ),
	      .cs         (sw_wr_en_3    ),
	      .we         (sw_be         ),		 
	      .data_in    (sw_reg_wdata  ),
	      
	      //List of Outs
	      .data_out   (reg_3         )
	      );

//  Register-4 
gen_32b_reg  #(32'h0) u_reg_4	(
	      //List of Inputs
	      .reset_n    (rst_n         ),
	      .clk        (mclk          ),
	      .cs         (sw_wr_en_4    ),
	      .we         (sw_be         ),		 
	      .data_in    (sw_reg_wdata  ),
	      
	      //List of Outs
	      .data_out   (reg_4         )
	      );

//  Register-5 
gen_32b_reg  #(32'h0) u_reg_5	(
	      //List of Inputs
	      .reset_n    (rst_n         ),
	      .clk        (mclk          ),
	      .cs         (sw_wr_en_5    ),
	      .we         (sw_be         ),		 
	      .data_in    (sw_reg_wdata  ),
	      
	      //List of Outs
	      .data_out   (reg_5         )
	      );

//  Register-6 
gen_32b_reg  #(32'h0) u_reg_6	(
	      //List of Inputs
	      .reset_n    (rst_n         ),
	      .clk        (mclk          ),
	      .cs         (sw_wr_en_6    ),
	      .we         (sw_be         ),		 
	      .data_in    (sw_reg_wdata  ),
	      
	      //List of Outs
	      .data_out   (reg_6         )
	      );

//  Register-7 
gen_32b_reg  #(32'h0) u_reg_7	(
	      //List of Inputs
	      .reset_n    (rst_n         ),
	      .clk        (mclk          ),
	      .cs         (sw_wr_en_7    ),
	      .we         (sw_be         ),		 
	      .data_in    (sw_reg_wdata  ),
	      
	      //List of Outs
	      .data_out   (reg_7         )
	      );

//  Register-8 
gen_32b_reg  #(32'h0) u_reg_8	(
	      //List of Inputs
	      .reset_n    (rst_n         ),
	      .clk        (mclk          ),
	      .cs         (sw_wr_en_8    ),
	      .we         (sw_be         ),		 
	      .data_in    (sw_reg_wdata  ),
	      
	      //List of Outs
	      .data_out   (reg_8         )
	      );

endmodule
