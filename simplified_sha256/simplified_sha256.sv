module simplified_sha256 #(parameter integer NUM_OF_WORDS = 20)(
	input  logic        clk, rst_n, start,
	input  logic [15:0] input_addr, hash_addr,
	output logic        done, memory_clk, memory_we,
	output logic [15:0] memory_addr,
	output logic [31:0] memory_write_data,
	input  logic [31:0] memory_read_data);

// FSM state variables 
enum logic [2:0] {IDLE, READ1, READ2, BLOCK, COMPUTE, WRITE1, WRITE2} state;

parameter integer SIZE = NUM_OF_WORDS * 32;
parameter integer blocks = ((NUM_OF_WORDS+2)/16) + 1;

// Local variables
logic [31:0] w[16];
logic [31:0] message[64];
logic [31:0] wt;
logic [31:0] S0, S1;
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [31:0] A, B, C, D, E, F, G, H;
logic [ 7:0] i, j;
logic [15:0] offset;
logic [ 7:0] num_blocks;
logic        enable_write;
logic [15:0] present_addr, write_addr;
logic [31:0] present_write_data;
logic [ 7:0] tstep;

// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

assign num_blocks = determine_num_blocks(NUM_OF_WORDS); 
assign tstep = (i - 1);

// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
assign memory_clk = clk;
assign memory_addr = present_addr + offset;
assign memory_we = enable_write;
assign memory_write_data = present_write_data;

// Function to determine number of blocks in memory to fetch
function logic [15:0] determine_num_blocks(input logic [31:0] size);
	return ((size+2)/16) + 1;
endfunction

//WORD EXPANSION
function logic [31:0] wtnew;
	logic [31:0] s0, s1; // internal signals
	begin
	s0 = ror(w[1],7) ^ ror(w[1],18) ^ (w[1] >> 3);
	s1 = ror(w[14], 17) ^ ror(w[14], 19) ^ (w[14] >> 10);
	wtnew = w[0] + s0 + w[9] + s1;
	end
endfunction


// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
	 
begin
    S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
    ch = (e & f) ^ ((~e) & g);
    t1 = h + S1 + ch + k[t] + w; 
    S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;
    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction

// Right rotation function
function logic [31:0] ror(input logic [31:0] in,
                          input logic [ 7:0] s);
   ror = (in >> s) | (in << (32 - s));
endfunction


// SHA-256 FSM 
always_ff @(posedge clk, negedge rst_n)
begin
	if (!rst_n) begin
		enable_write <= 1'b0;
		state <= IDLE;
	end 
	else case (state)
		// Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
		IDLE: begin 
			if(start) begin
				//Initialize Hash	
				h0 <= 32'h6a09e667;		
				h1 <= 32'hbb67ae85;	
				h2 <= 32'h3c6ef372;	
				h3 <= 32'ha54ff53a;	
				h4 <= 32'h510e527f;	
				h5 <= 32'h9b05688c;	
				h6 <= 32'h1f83d9ab;	
				h7 <= 32'h5be0cd19;
			
				A <= 32'h6a09e667;		
				B <= 32'hbb67ae85;	
				C <= 32'h3c6ef372;	
				D <= 32'ha54ff53a;	
				E <= 32'h510e527f;	
				F <= 32'h9b05688c;	
				G <= 32'h1f83d9ab;	
				H <= 32'h5be0cd19;
				
				enable_write <= 0;
				offset <= 0; // read/write offset
				present_addr <= input_addr;
				
				i <= 0; 
				j <= 0; 
				
				state <= READ1;
			end
		end 
		
		READ1: begin
			state <= READ2;
		end
		
		READ2: begin
			if (offset < NUM_OF_WORDS) begin
				message[offset] <= memory_read_data;
				offset <= offset + 1;
				state <= READ1;
			end
			else begin
				offset <= 16'b0;
				message[NUM_OF_WORDS] <= 32'h80000000;
				for (int m = NUM_OF_WORDS+1; m < (blocks*16-1); m++) begin
					message[m] <= 0;
				end
				message[blocks*16 - 1] <= SIZE;
				
				state <= BLOCK;
			end
		end
		
		BLOCK: begin
			if (j < num_blocks) begin
				for (int m = 0; m < 16; m++) begin
					w[m] <= message[m + (j*16)];
				end
				j <= j + 1;
				state <= COMPUTE;
			end
			else begin
				state <= WRITE1;
			end
		end
			
		COMPUTE: begin //perform sha256 algorithm
			if (i < 64) begin
				{A, B, C, D, E, F, G, H} <= sha256_op(A, B, C, D, E, F, G, H, w[0], (i));
				for (int n = 0; n < 15; n++) w[n] <= w[n+1];
				w[15] <= wtnew();
				i <= i + 1;
				state <= COMPUTE;
			end
			else begin
				h0 <= h0 + A;
				h1 <= h1 + B;
				h2 <= h2 + C;
				h3 <= h3 + D;
				h4 <= h4 + E;
				h5 <= h5 + F;
				h6 <= h6 + G;
				h7 <= h7 + H;
				
				A <= h0 + A;
				B <= h1 + B;
				C <= h2 + C;
				D <= h3 + D;
				E <= h4 + E;
				F <= h5 + F;
				G <= h6 + G;
				H <= h7 + H;
			
				i<=8'b0;
				state <= BLOCK;
			end
		end
		
		WRITE1: begin
			enable_write <= 1'b1;
			present_addr <= hash_addr;
			present_write_data <= h0;
			state <= WRITE2;
		end
		
		WRITE2: begin // write result to memory
			case(offset+1)
				1: present_write_data <= h1;
				2: present_write_data <= h2;
				3: present_write_data <= h3;
				4: present_write_data <= h4;
				5: present_write_data <= h5;
				6: present_write_data <= h6;
				7: present_write_data <= h7;
			endcase
			offset <= offset + 1;
			if (offset < 8) begin
				state <= WRITE2;
			end
			else begin
				state <= IDLE;
			end
		end 
	endcase
end
 
// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == IDLE);

endmodule