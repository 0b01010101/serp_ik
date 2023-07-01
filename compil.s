BITS 64
 
%define __NR_read 0
%define __NR_write 1
%define __NR_open  2
%define __NR_close 3
%define __NR_exit 60

%define line_lenght 80
%define line_max    2000
%define prog_size   line_lenght*line_max
%define f_stack_size 560
%define len_tmp_var  127
%define len_tmp_par  127
%define len_mas_buf  1300


SECTION .data
;vars:    resb   line_max ;27*2*4
str_now: times 2   dd 0     ;pointer to the string currently being executed
stack:   times 2   dd 0
func_stack: times 2 dd 0
func_rbx:   times 2 dd 0
vars:    times 540 db 0          ;vars <a-z> functions <A-Z>; byte[0]-count of parametrs if this function; byte[1]-count of local vars in func. if this func.; byte[2-9]-addr
funcs:   times f_stack_size db 0          ;stack for functions; max count recursion functions(with 7 parameters) = 10
line:    times line_lenght db 0  ;line of code from stdin
prog:    times prog_size   db 0  ;memmory for all program
tmp_var: times len_tmp_var db 0
tmp_par: times len_tmp_par db 0
mas_buff_str: times len_mas_buf db 0
mas_buff:times len_mas_buf db 0
mas_sp:  times 2 dd 0

err_syntax_msg: db  "ERROR syntax!", 0x0A

operands:

   db 2, "if"
   dq _if_handl

   db 3, "def"
   dq _func_decl
   
   db 3, "dem"
   dq var_anal

   db 3, "new"
   dq _start

   db 3, "run"
   dq _run_handl

   db 4, "list"
   dq _list_handl

   db 4, "goto"
   dq _goto_handl

   db 5, "print"
   dq _print_handl

   db 5, "input"
   dq _input_handl
re_tu_rn:
   db 6, "return"
   dq _return_handl

   db 0

GLOBAL  _start
 
SECTION .bss
 
%define bufsize 1024
buffer  resb    bufsize


SECTION .text
 
_start:
      cld
      mov   rdi, prog
      mov   rcx, prog_size 
      mov   rax, 0x0D
      rep   stosb
      mov   [stack], rsp
      mov   rax, funcs
      add   rax, f_stack_size  
      mov   [func_stack], rax
      mov   rax, mas_buff
      mov   [mas_sp], rax

      cmp   qword[rsp], 1
      jle   _main
      mov   rdi, [rsp+16]
      call  sys_open
      push  rax
      xchg  rax, rdi
      call  sys_file_read 
      mov   qword[str_now], 0x00
      call  _run_handl
      pop   rdi
      call  sys_file_close
      call  sys_exit

_main:
      xor   rax, rax
      mov   rsp, [stack]
      mov   [str_now], rax
      mov   al, '>'
      call  input_char
      call  str_to_dec
      or    rax, rax
      je    intr_mode
      call  find_addr
      xchg  rax, rdi
      mov   rcx, line_lenght
      rep   movsb
      call  inp_line_clear
      jmp   _main
   intr_mode:
      call  _execute
      jmp   _main

   inp_line_clear:
         mov   rsi, line
         mov   rcx, line_lenght
      cd:
         mov   byte[rsi], 0x00
         inc   rsi
         dec   rcx
         test  rcx, rcx
         jnz   cd 
      ret

_if_handl:
   call  _expres
   or    rax, rax
   je    ret_glob   
_execute:
      call  skip_spaces
      cmp   byte [rsi], 0x0D
      je    ret_glob
      mov   rdi, operands
   next_entry:
      xor   rcx, rcx
      mov   cl, [rdi]   
      test  cx, cx
      je    to_get_var
   
      push  rsi
      inc   rdi
      rep   cmpsb
      jne   no_equal
      
      pop   rax
      call  skip_spaces
      jmp   [rdi]
   no_equal:
      add   di, cx
      add   di, 8
      pop   rsi
      jmp   next_entry 

to_get_var:
      call  get_var
      push  rax
      lodsb
      cmp   al, '='
      je    assign
      cmp   al, '('
      je    func_mk
      cmp   al, '['
      je    massive_def 
      cmp   al, ';'
      je    var_def
   err_print:
      
      jmp   _main

_input_handl:
      call  get_var
      push  rax
      mov   al, '?'
      call  input_char
assign:
      call  _expres
      pop   rdi
      stosq          ;???????????
   ret

   massive_def:
      pop   rdi
   ret
   var_def:
      pop   rdi
   ret

_func_decl:
   call  get_var
   mov   rcx, [str_now]
  ; add   rcx, line_lenght
   xchg  rbx,  rax
   mov   [rbx], rcx
   xor   rdx, rdx
   mov   rdi, re_tu_rn
   xor   rcx, rcx
   mov   cl,  [rdi]
   inc   rdi
   ch_loop:
   ;call  skip_spaces
   lodsb 
   cmp   al, 0x0D    ;'\n'
   je   ch_nl
   cmp   al, ';'
   jne   ch_h
;   mov   rax, [str_now]
;   add   rax, line_lenght
   ch_nl:
   cmp   rcx, 0xffff
   je    ch_eh
   
   mov   rax, [str_now]
   mov   rsi, rax
   add   rax, line_lenght
   mov   [str_now], rax
   jmp   ch_loop
   ch_h:
   cmp   al, '#'
   jne   ch_a
   call  ch_loc_var
   jmp   ch_loop
   ch_a:
   cmp   al, '@'
   jne   ch_r
   call  ch_loc_par 
   jmp   ch_loop
   ch_r:
   push  rcx
   push  rsi
   push  rdi
   rep   cmpsb
   jne   ch_no
   mov   rcx, 0xffff
   jmp   ch_loop
   ch_eh:
   add   rsp, 24
;   mov   rax, [str_now]
;   add   rax, line_lenght
;   mov   [str_now], rax
   mov   [rbx-2], dx
   call  clear_loc_var
ret
   ch_no:
   pop   rdi
   pop   rsi
   pop   rcx
   jmp   ch_loop
ret

   ch_loc_par:
         push  rdx
         push  rbx

         xor   rdx, rdx
         mov   rbx, tmp_par
         lodsb
      p_l:
         cmp   byte[rbx], 0
         je    p_a
         cmp   al, byte[rbx]
         je    p_e
         inc   rbx
         inc   rbx
         inc   rdx
         jmp   p_l
      p_a:
         mov   byte[rbx], al
         mov   byte[rbx+1], dl
         mov   byte[rsi-1], dl 
         
         pop   rbx
         pop   rdx
         inc   dl 
      ret
      p_e: 
         mov   al, byte[rbx+1]
         mov   byte[rsi-1], al 
         pop   rbx
         pop   rdx
      ret

   ch_loc_var:
         push  rcx
         push  rdi
         push  rbx
         push  rdx
         push  rsi

         xor   rcx, rcx
      l_v_l:
         lodsb 
         cmp   al, '['
         je    v_s
         cmp   al, '='
         je    v_s
         cmp   al, '('
         je    v_s
         cmp   al, ';'
         je    v_s
         inc   rcx
         jmp   l_v_l
      v_s:
         pop   rsi
         xor   rbx, rbx
         mov   rdi, tmp_var
      v_l:
         add   rdi,  3
         cmp   cl, [rdi-1]
         je    siz_ok
         cmp   byte[rdi-1], 0
         je    siz_0         
      v_nxt:
         mov   al, byte[rdi-1]
         and   rax, 0xff
         add   rdi, rax
         inc   rbx
         jmp   v_l

      siz_ok:
         push  rsi
         push  rcx
         push  rdi

         rep   cmpsb
         pop   rdi
         pop   rcx
         pop   rsi
         jne   v_nxt
      v_find:
         xor   rax, rax
         add   rsi, rcx
         pop   rdx
         jmp   v_exit
      siz_0:
         push  rdi
         mov   bx, word[rdi-3]
         mov   byte[rdi-1], cl
         push  rbx
         push  rcx
         rep   movsb

         mov   ax, 1
         cmp   byte[rsi], '['
         jne   no_mas

         push  rsi
         inc   rsi
         call  _expres
         pop   rsi
      no_mas:
         pop   rcx
         pop   rbx
         add   ax, bx
         mov   word[rdi], ax
         pop   rdi
         
         pop   rdx
         mov   dh, al
      v_exit:
         mov   byte[rsi-3], 0x11 
         mov   ax, word[rdi-3]
         mov   word[rsi-2], ax
         cmp   cl, 3 
         jle   v_ret
         sub   rsi, rcx
         sub   cl, 3
      v_mod:
         mov   byte[rsi], ' '
         dec   cl
         inc   rsi
         test  cl, cl
         jnz   v_mod
         add   rsi, 3
      v_ret:
         cmp   byte[rsi], ']'
         je    va_ret
         cmp   byte[rsi], ')'
         je    va_ret
         cmp   byte[rsi], '='
         je    va_ret
         cmp   byte[rsi], ';'
         je    va_ret
         inc   rsi
         jmp   v_ret
      va_ret:
         inc  rsi
         pop  rbx
         pop  rdi
         pop  rcx
      ret

   clear_loc_var:
         mov   rdx, tmp_var 
         mov   rcx, len_tmp_var
      c_l_v:
         mov   byte[rdx], 0 
         inc   rdx
         dec   rcx
         test  rcx, rcx
         jnz   c_l_v
      ret

   func_mk:
         mov   rax, [str_now]
        ; add   rax, line_lenght 
         pop   rdi 
         push  rax

         xor   rdx, rdx
       check_param:
         cmp   byte[rsi], ')'
         je    form_func_stack
         cmp   byte[rsi], ','
         je   check_param3 
       check_param2:
         push  rdx
         call  _expres
         pop   rdx
         push  rax
         inc   rdx
         jmp   check_param
       check_param3:
         inc   rsi
         jmp   check_param 
         
       form_func_stack:
         mov   cl, byte[rdi-2]
         cmp   dl, cl 
         je    aa
         call  err_print
       aa:
         mov   rcx, [func_stack]
       form_func_stack2:
         cmp   rdx, 0
         je    end_form
         pop   rax
         dec   rdx
         xchg  rcx, rsp
         push  rax
         xchg  rcx, rsp
         jmp   form_func_stack2
       end_form:
         mov   rax, [func_stack]
         mov   rbx, [func_rbx]
         push  rax
         push  rbx

         mov   [func_rbx], rcx
         mov   al, byte[rdi-1]
         mov   dl, 8
         mul   dl
         and   rax, 0xffff
         sub   rcx, rax

         mov   [func_stack], rcx
         mov   [stack], rsp
         mov   rsp, rcx    ;[func_stack]
         
         mov   rax, [rdi]
        ; mov   [str_now], rax
         call  to_nxt_line
         mov   rax, rdx
         mov   rsp, [stack]

         pop   rbx
         pop   rdx
         mov   [func_rbx], rbx
         mov   [func_stack], rdx
         pop   rcx
         mov   [str_now], rcx
      ret

   _return_handl:
         ;call _expres
         lodsb
         cmp   al, 0x00
         je    pret_ret
         cmp   al, ';'
         jne   ret_var
      pret_ret:
         mov   rdx, 0
         jmp   ret_ret
      ret_var:
         dec   rsi
         call  get_var
         mov   rdx, [rax]
      ret_ret:
         mov   rax, prog+prog_size
         mov   [str_now], rax
      ret
   

_list_handl:
      xor   rax, rax
   nxt_line:
      push  rax
      call  find_addr
      xchg  rax, rsi
      cmp   byte [rsi], 0x0D
      je    empty_line
      pop   rax
      push  rax
      call  print_dec
   nxt_char:
      lodsb 
      call  output_char
      cmp   al, 0x0D
      jne   nxt_char 
   empty_line:
      pop   rax
      inc   rax
      cmp   rax, line_max
      jne   nxt_line

   ret_glob:
      ret

_run_handl:
      xor   rax, rax
      jmp  to_goto 
_goto_handl:
      call  _expres
   to_goto:
      call  find_addr
      cmp   qword [str_now], 0
      je    to_nxt_line
      mov   [str_now], rax
      ret
   to_nxt_line:
      push  rax
      pop   rsi
      add   rax, line_lenght 
      mov   [str_now], rax
      call  _execute
      mov   rax, [str_now]
      cmp   rax, prog + prog_size 
      jne   to_nxt_line 
   ret

_print_handl:
      lodsb
      cmp   al, 0x0D
      je    output_line
      cmp   al, 0x40
      jnc   print_var
      cmp   al, '"'
      jne   no_quote
   next_char:
      lodsb
      cmp   al, '"'
      je    to_semicolon
      call  output_char
      cmp   al, 0x0D
      jne   next_char
   ret
   no_quote:
      dec   si
      call  _expres
      call  print_dec 
   to_semicolon:
      lodsb
      cmp   al, ';'
      jne   output_line
   ret
   print_var:
      call  get_var2
      xchg  rax, rbx
      mov   rax, [rbx]
      call  print_dec
      call  output_line
   ret

_expres:
      call  expr2_left
   add_sub:
      cmp   byte [rsi], '+'
      je    to_add
      cmp   byte [rsi], '-'
      jne   ret_glob
      
      push  rax
      call  expr2_right
      pop   rbx
      xchg  rax, rbx
      sub   rax, rbx
      jmp   add_sub
   to_add:
      push  rax
      call  expr2_right
      pop   rbx
      add   rax, rbx
      jmp   add_sub

   expr2_right:
      inc   rsi
   expr2_left:
      call  expr3_left
   mul_or_div:
      cmp   byte [rsi], '*'
      je    to_mul
      cmp   byte [rsi], '/'
      jne   ret_glob

      push  rax
      call  expr3_right
      pop   rbx
      xchg  rax, rbx
      idiv  rbx
      jmp   mul_or_div
   to_mul:
      push  rax
      call  expr3_right
      pop   rbx
      imul  rbx
      jmp   mul_or_div

   expr3_right:
      inc   rsi
   expr3_left:
      call  skip_spaces
      lodsb
      cmp   al, '('
      jne   no_param
      call  _expres
      cmp   byte [rsi], ')'
      jne   err_print
      jmp   skip_spaces2
   no_param:
      cmp   al, 0x40    ;'A'-'~'
      ja    yes_var
      cmp   al, 0x40    ;'@'
      je    func_param
      cmp   al, 0x23    ;'#'
      je    func_var

      dec   rsi
      call  str_to_dec
      jmp   skip_spaces
   yes_var:
      cmp   byte[rsi], 0x40
      jle   yes_var1
      cmp   byte[rsi], 0x5A    ;'Z'
      jle   yes_big_var
      cmp   byte[rsi], 0x5E    ;'^'
      jle   yes_var1
      cmp   byte[rsi], 0x7A    ;'z'
      jle   yes_big_var 
   yes_var1:
      cmp   al, 0x5A    ;'Z'
      jle   yes_func
      cmp   byte[rsi], '('
      je    yes_func
      call  get_var2
      xchg  rax, rbx
      mov   rax, [rbx]
   ret 
   yes_big_var:
      dec   rsi
      call  var_anal
      mov   rcx, [rax]
      xchg  rax, rcx
   ret
   yes_func:
      ;lodsb
      ;cmp   al, '('
      ;jne   ret_glob
      ;call  func_mk
      dec    rsi
      jmp    to_get_var
   ret
   func_param:
      push  rbx
      lodsb
      and   rax, 0xff
      mov   rbx, [func_rbx]
      mov   ecx, 8
      mul   ecx 
      add   rbx, rax
      mov   rax, [rbx-8]
      pop   rbx 
   ret
   func_var:
      push  rbx
      xor   rbx, rbx
      call  skip_spaces
      add   rsi, 3
      cmp   byte[rsi], '['
      je   fnc_mas
      push  rsi
      jmp   fnc_vr
   fnc_mas:
      push  rsi
      inc   rsi
      call  _expres
      mov   rbx, rsi
      inc   rbx
      pop   rsi
      push  rbx
      xchg  rax, rbx
   fnc_vr:
      mov   ax, word[rsi-2] 
      add   ax, bx
      and   rax, 0xffff
      mov   rbx, [func_rbx]
      mov   ecx, 8
      mul   ecx
      sub   rbx, rax
      mov   rax, [rbx-8] 

      pop   rsi
      pop   rbx 
   ret

  find_addr:
      mov   rcx, line_lenght
      mul   rcx
      add   rax, prog
   ret


   get_var:
      lodsb
      cmp   al, 0x40       ;'@'
      jne   get_varf
      lodsb
      and   rax, 0xff 
      mov   rbx, [func_rbx]
      mov   ecx, 8
      mul   ecx
      add   rbx, rax
      sub   rbx, 8
      xchg  rax, rbx
      jmp   skip_spaces
   get_varf:
      cmp   al, 0x23       ;'#'
      jne   get_var2
      call  skip_spaces
      add   rsi, 3
      cmp   byte[rsi], '['
      je    get_mas
      jmp   get_l_vr
   get_mas:
      push  rsi
      inc   rsi
      call  _expres
      inc   rsi
      xchg  rax, rcx
      pop   rbx
   get_l_vr: 
      mov   ax, word[rbx-2]
      add   ax, cx
      and   rax, 0xffff
      mov   rbx, [func_rbx]
      mov   ecx, 8
      mul   ecx
      sub   rbx, rax
      sub   rbx, 8 
      xchg  rax, rbx
      jmp   skip_spaces
   get_var2:
      cmp   byte[rsi], ' '
      je    gv2
      cmp   byte[rsi], '='
      je    gv2 
      cmp   byte[rsi], '('
      je    gv2
      cmp   byte[rsi], '['
      je    get_big_name
      cmp   byte[rsi], 0x40
      jle   gv2
      jne   get_big_name
   gv2:
      and   al,0x3f; 0x1F
      mov   ah, 0
      mov   rcx, 10
      mul   cx
   
  ;    shl   rax, 3          ;al * 8
      mov   rbx, vars
      mov   rcx, 0x000000000000ffff
      and   rax, rcx
      add   rax, rbx 
      add   rax, 2
   skip_spaces:
      cmp   byte[rsi], ' '
      jne   ret_glob  
   skip_spaces2:
      inc   rsi
      jmp   skip_spaces
   get_big_name:
      dec   rsi
      jmp   var_anal

   print_dec:
       xor      rdx, rdx
       mov      rcx, 10
       div      rcx
       or       rax, rax
       push     rdx
       je       to_print_char 
       call     print_dec
      to_print_char:
       pop      rax
       add      rax, '0'
       mov      [buffer], rax
       mov      rdx, 1
       jmp      sys_write 

   str_to_dec:
        xor     rbx, rbx
      next_digit:
        lodsb
        sub     al, '0'
        cmp     al, 10
        cbw
        cwde
        xchg    eax, ebx
        jnc     not_digit
        mov     ecx, 10
        mul     cx
        add     ebx, eax
        jmp     next_digit
      not_digit:
        dec     si
      ret
 
   output_char:
      push  rax
      cmp   al, 0x0D
      mov   rdx, 1
      jne   to_out
   output_line:
      mov   al, 0x0D
      mov   [buffer+1], al
      mov   rdx, 2
      mov   al, 0x0A
   to_out:
      mov   [buffer], al
      call  sys_write
      pop   rax
   ret

   input_char:
      mov   [buffer], al
      mov   rdx, 1
      call  sys_write 
      call  sys_read
   ret
;======================================================================================================================================================================================

   sys_read:
        mov     rax, __NR_read   ; "read" function number
        xor     rdi, rdi         ; console read file descriptior (0)
        mov     rsi, line        ; buffer address
        mov     rdx, line_lenght ; buffer size
        syscall                  ; read from console (returns read bytes count in rax) ret sys_write: ;mov     rdx, rdx         ; number of bytes to write mov     rax, __NR_write  ; "write" function number mov     rdi, 1           ; console write file descriptior mov     rsi, buffer syscall                  ; write to console ret
      ret
   sys_exit: 
        mov     rax, __NR_exit   ; "exit" function number
        xor     rdi, rdi         ; error code (0)
        syscall                 ; terminate the program
      ret
   sys_write:
         push  rsi
         mov   rax, __NR_write
         mov   rdi, 1
         mov   rsi, buffer
         syscall
         pop   rsi
      ret
   sys_open:
         mov   rax, __NR_open
         mov   rsi, 0
         mov   rdx, 0
         syscall
      ret
   sys_file_read:
         mov   rax,  __NR_read
         mov   rsi, prog
         mov   rdx, prog_size 
         syscall
      ret
   sys_file_close:
         mov   rax, __NR_close
         syscall
      ret
;======================================================================================================================================================================================

var_anal:
     ; dec    rsi
     ; call   skip_spaces
      push   rsi
      xor   rcx, rcx
   v_a_l:
      lodsb  
      cmp   al, '['
      je    mas_anal
      cmp   al, '('
      je    func_anal
      inc   rcx
      jmp   v_a_l 
   mas_anal:                        ;| - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
      pop   rsi                     ;| indx | size of massive | start addr in memory | size of name |  name   |
      mov   rdi, mas_buff_str           ;| 2 byt|    2 bytes      |       8 bytes        |    1 byte    | ? bytes |
      xor   rdx, rdx                ;| _ _ _| _ _ _ _ _ _ _ _ | _ _ _ _ _ _ _ _ _ _ _| _ _ _ _ _ _ _| _ _ _ _ |
   mas_ch:
      add   rdi, 13     ;name
      cmp   cl, [rdi-1] ;size of name
      je    mas_size
      cmp   byte[rdi-1], 0
      je    mas_zer
   mas_nxt:
      mov   rax, [rdi-1] ;size of name
      add   rdi, rax
      ;add   rdi, 2+8       ;bytes for size and adr
      inc   dx           ;indx in mas_buff_str
      jmp   mas_ch
      mas_size:
      push  rsi
      push  rcx
      push  rdi
      rep   cmpsb           ; [rsi], [rdi]
      pop   rdi
      pop   rcx
      pop   rsi
      jne   mas_nxt
      mas_find:
      add   rsi, rcx

      push  rsi
      push  rdx
      push  rcx
      inc   rsi
      call  _expres
      pop   rcx
      pop   rdx
      pop   rsi

      mov   bx, 8
      mul   bx
      and   rax, 0xfffffff 
      mov   rbx, [rdi-9]
      add   rax, rbx
      jmp   mas_exit
      mas_zer:
      push  rdx
      push  rsi
      push  rcx
      mov   word [rdi-13], dx 
      mov   byte[rdi-1], cl
      mov   rdx, [mas_sp]
      mov   [rdi-9], rdx      ;addr

      add   rsi, rcx
      inc   rsi
      call  _expres
      mov   word[rdi-11], ax
      pop   rcx
      pop   rsi
      pop   rdx
      mov   bx, 8
      mul   bx
      and   rax, 0xfffffff
      ;add   rax, 8
      add   [mas_sp], rax
      push  rcx
      rep   movsb 
      pop   rcx
      mas_exit:
      mov   byte[rsi-3], 0x11       ;'DC1'(asc2) - identificator of massive
      mov   word[rsi-2], dx
      cmp   cl, 3
      jle   ret_glob
      sub   rsi, rcx
      sub   cl, 3
      m_e_r:
      mov byte[rsi], 0x00
      dec   cl
      inc   rsi
      test  cl, cl
      jnz   m_e_r
      add   rsi, 3
      mer:
      inc   rsi
      cmp   byte[rsi], ']'
      jne   mer
      inc   rsi
   ret
   func_anal:

      pop   rsi 
   var_ret:
      pop   rsi
      
ret







