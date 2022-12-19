// PARALLEL (OPTIMIZED) IMPLEMENTATION
module bitcoin_hash (input  logic        clk, reset_n, start,
                     input  logic [15:0] message_addr, output_addr,
                     output logic        done, mem_clk, mem_we,
                     output logic [15:0] mem_addr,
                     output logic [31:0] mem_write_data,
                     input  logic [31:0] mem_read_data);

parameter num_nonces = 16;

// Local variables
logic 	[31:0] message[32];
logic 	[15:0] present_addr; 
logic 	[31:0] present_write_data;
logic 	[15:0] offset;
logic   [31:0] h[16][0:7]; // hash output form sha256
logic   [31:0] fh[0:7]; // initial hash
logic   [31:0] hash_bit[16][0:7]; // hash input to sha256
logic 	[31:0] message_bit[16][0:15]; // message input to sha256
logic          enable_write; 
logic          done_sha[num_nonces];
logic   	   start_bit; 

// Instantiate SHA-256 modules
genvar q;
generate 
	for (q = 0; q < num_nonces; q++) begin : generate_sha256_blocks
		sha256_inst block (
			.clk(clk),
			.reset_n(reset_n),
			.start(start_bit),
			.done(done_sha[q]),
			.output_hash(h[q]), 
			.input_hash(hash_bit[q]),
			.input_message(message_bit[q])	
		);
	end : generate_sha256_blocks
endgenerate			

enum logic [4:0] {IDLE, READ, BUFFER1, PHASE1, BUFFER2, PHASE2, BUFFER3, PHASE3, WRITE} state;

parameter int k[64] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

assign mem_clk = clk;
assign mem_addr = present_addr + offset;
assign mem_we = enable_write;
assign mem_write_data = present_write_data;

always_ff @(posedge clk, negedge reset_n) begin
	if (!reset_n) begin
		state <= IDLE;
	end
	else
		case (state)
			IDLE: begin
				if (start) begin
					
					// Initial hashing
					fh[0] <= 32'h6a09e667;
					fh[1] <= 32'hbb67ae85;
					fh[2] <= 32'h3c6ef372;
					fh[3] <= 32'ha54ff53a;
					fh[4] <= 32'h510e527f;
					fh[5] <= 32'h9b05688c;
					fh[6] <= 32'h1f83d9ab;
					fh[7] <= 32'h5be0cd19;
					
					offset <= 0;
					
					present_addr <= message_addr;
					
					state <= READ;
				end
			end
			
			READ: begin
				// reading in the first 19 words
				if (offset < 20) begin  
					message[offset-1] <= mem_read_data;
					offset <= offset + 1;
					state <= READ;
				end
				else begin 
					// pad the message with zeros
					message[20] <= 32'h80000000; // leading 1 bit
					
					for (int m = 21; m < 31; m++) begin
						message[m] <= 32'h00000000; 
					end
					
					message[31] <= 32'd640; // SIZE = 640 BITS
				
					// input message in 0 sha256
					for (int n = 0; n < 16; n++) begin 
						for (int m = 0; m < 16; m++) begin 
							message_bit[n][m] <= message[m];
						end
					end
					
					// input hash to 0 sha256
					for (int m = 0; m < 8; m++) begin
						hash_bit[0][m] <= fh[m];
					end

					offset <= 0;
					start_bit <= 1;
					state <= BUFFER1;
				end	
			end
			
			BUFFER1: begin 
				// wait until the first input finishes reading
				if (!done_sha[0]) state <= PHASE1;
			end
			
			PHASE1: begin
				if (done_sha[0]) begin
				
					for (int n = 0; n < 16; n++) begin
						for (int m = 0; m < 8; m++) begin 
							hash_bit[n][m] <= h[0][m];
						end
						
						for (int m = 0; m < 16; m++) begin
							if (m == 3) begin
								message_bit[n][m] <= n; // assign nonce value								
							end
							// add message to 16 sha256 modules
							else message_bit[n][m] <= message[m+16]; 
						end
					end
					start_bit <= 1;
					state <= BUFFER2;
				end
				else state <= PHASE1;
			end
			
			BUFFER2: begin 
				if (!done_sha[0]) state <= PHASE2;
			end
			
			PHASE2: begin
				if (done_sha[0]) begin

					for (int n = 0; n < 16; n++) begin
						for (int m = 0; m < 8; m++) begin 
							// add the initial hash
							hash_bit[n][m] <= fh[m]; 
						end 
						
						for (int m = 0; m < 8; m++) begin 
							// add output hash to message
							message_bit[n][m] <= h[n][m];
						end
						
						// pad the message with zeros
						message_bit[n][8] <= 32'h80000000;
						
						for (int m = 9; m < 15; m++) begin
							// padding with zeros
							message_bit[n][m] <= 32'h00000000; 
						end
						
						message_bit[n][15] <= 32'd256; // SIZE = 256 BITS
					end
				
					start_bit <= 1;
					state <= BUFFER3;
				end
				else state <= PHASE2;
			end
			
			BUFFER3: begin  
				if (!done_sha[0]) state <= PHASE3;
			end
			
			PHASE3: begin
				if (done_sha[0]) begin 
					// read first hash from each sha256 output
					for (int n = 0; n < num_nonces; n++) begin
						hash_bit[n][0] <= h[n][0];
					end
									
					start_bit <= 0;
					state <= WRITE;
				end
			end
			
			WRITE: begin
				enable_write <= 1;
				present_addr <= output_addr - 1;
				
				// write first hash from each sha256 block output
				if (offset < 16) begin 
					present_write_data <= hash_bit[offset][0]; 
					offset <= offset + 1;
				end
				else begin
					state <= IDLE;
					offset <= 0;
				end
			end
		endcase
end

assign done = (state == IDLE);

endmodule