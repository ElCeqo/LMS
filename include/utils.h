// This function handles errors by printing them to stderr and aborting the program.
void handle_error();

/* String Manipulation APIS */

// Convert unsigned char to hex string
void u8str(uint8_t x,uint8_t* out);

// Convert unsigned short int to hex string
void u16str(uint16_t x, uint8_t *out);

// Convert unsigned int to hex string
void u32str(uint32_t x, uint8_t *out);

// Convert hex string to unsigned int
uint32_t strTou32(const uint8_t *in);

// Interpret a byte string as a sequence of w-bit values
uint8_t coef(const uint8_t *S, size_t i, int w);

void hex_encode(const uint8_t *in, size_t len, char *out);