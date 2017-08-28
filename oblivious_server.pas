//Copyright 2017 Andrey S. Ionisyan (anserion@gmail.com)
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.

//учебный шаблон сервера забывчивого протокола передачи сообщений

//Общая постановка задачи.
//Сервер A имеет два сообщения S0 и S1
//клиент B имеет право получить одно (и только одно) из сообщений S0 или S1
//Сервер A не имеет права знать какое именно сообщение выбрал и получил клиент B

// протокол забывчивой передачи сообщений
// 1. Сервер A генерирует публичный (N,e) и секретный (N,d) ключи RSA
// 2. Сервер A генерирует 2 произвольных числа x0 и x1, пригодных
//    для RSA-кодирования (публикуются)
// 3. Клиент B делает секретный выбор какое из сообщение S0 или S1
//    он возьмет у сервера: если S0, то b=0, иначе b=1.
// 4. Клиент B генерирует произвольное секретное число k, пригодное для RSA.
// 5. Клиент B вычисляет и публикует v=(x_b+k^e) mod N
// 6. Сервер A вычисляет и публикует два возможных варианта декодирования
//    m0=S0+(v-x0)^d mod N
//    m1=S1+(v-x1)^d mod N
// 7. Клиент B производит окончательную фазу вычислений, однозначно 
//    декодируя только одно из полученных сообщений (другое остается секретным)
//    S_b=m_b-k

program oblivious_server;
var
   n,d,e:integer; //ключи RSA
   s0,s1:string; //сообщения, хранимые на сервере
   x0,x1:string; //числа шага 2 протокола в текстовом (бинарном) формате
   v:string; //результат шага 5 от клиента в текстовой (битовой) форме
   s,c,ss,cc:string; //вспомогательные переменные
   x0_dec,x1_dec,m0_dec,m1_dec,s_dec,c_dec,v_dec:integer; //вспомогательные переменные
   i,j,block_size,blocks_num,align_s,tmp:integer; //вспомогательные переменные
begin
   //ввод исходных данных
   writeln('Oblivious transfer server');
   writeln('n,d,e - RSA keys (numbers)');
   writeln('s0,s1 - text messages (binary codes)');
   //ввод ключей RSA
   write('n='); readln(n);
   write('d='); readln(d);
   write('e='); readln(e);
   //вычисление размера блока
   block_size:=0; tmp:=1;
   while tmp<n do begin tmp:=tmp*2; block_size:=block_size+1; end;
   block_size:=block_size-1;
   writeln('input block size=',block_size);
   writeln('output block size=',block_size+1);
   writeln;
   
   //ввод бинарного кода сообщений, хранимых на сервере
   //(предполагается равная длина сообщений)
   repeat
   write('(for default s0="0" input ".") s0=');readln(s0);if s0='.' then s0:='0';
   //выравнивание бинарного кода путем добавления нулей слева
   align_s:=block_size-(length(s0) mod block_size);
   if align_s=block_size then align_s:=0;
   for i:=1 to align_s do s0:='0'+s0;
   //печать выровненного бинарного кода s0
   writeln('add ',align_s,' zero bits to S0');
   write('S0=');
   for i:=1 to length(s0) do
   begin
      write(s0[i]);
      if (i mod block_size)=0 then write(' ');
   end;
   writeln; writeln;
   
   write('(for default s1="1" input ".") s1=');readln(s1);if s1='.' then s1:='1';
   //выравнивание бинарного кода путем добавления нулей слева
   align_s:=block_size-(length(s1) mod block_size);
   if align_s=block_size then align_s:=0;
   for i:=1 to align_s do s1:='0'+s1;
   //печать выровненного бинарного кода s1
   writeln('add ',align_s,' zero bits to S1');
   write('S1=');
   for i:=1 to length(s1) do
   begin
      write(s1[i]);
      if (i mod block_size)=0 then write(' ');
   end;
   writeln;
   if length(s0)<>length(s1) then writeln('ERROR: length(S0)<>length(S1)');
   until length(s0)=length(s1);
   writeln('===========================');
   
   //------------------------------------------------------
   //шаг 1 протокола (публикация открытой части ключей RSA)
   //------------------------------------------------------
   writeln('public key: N=',N);
   writeln('public key: E=',e);
   writeln;
   
   //------------------------------------------------------
   //шаг 2 протокола (генерация и публикация чисел x0 и x1)
   //------------------------------------------------------
   randomize;
   //генерация x0 на 1 бит меньше размера блока
   x0:=''; x0_dec:=0;
   for j:=1 to block_size-1 do
     if random(2)=1 then begin x0:=x0+'1'; x0_dec:=x0_dec*2+1; end
                    else begin x0:=x0+'0'; x0_dec:=x0_dec*2; end;

   //генерация x1 на 1 бит меньше размера блока
   x1:=''; x1_dec:=0;
   for j:=1 to block_size-1 do
     if random(2)=1 then begin x1:=x1+'1'; x1_dec:=x1_dec*2+1; end
                    else begin x1:=x1+'0'; x1_dec:=x1_dec*2; end;

   //публикация x0 и x1
   writeln('random: x0=',x0_dec:4,' = ',x0);
   writeln('random: x1=',x1_dec:4,' = ',x1);
   writeln;
   
   //------------------------------------------------------
   //шаг 6 протокола (шаги 3-5 на стороне клиента)
   //расчет и публикация блоков сообщений S0 и S1
   //согласно полученному v=(x_b+k^e) mod N
   //------------------------------------------------------
   write('waiting from client: V='); readln(v);
   //переводим v из текстового (бинарного) в числовой формат
   v_dec:=0;
   for j:=1 to length(v) do
   begin
     v_dec:=v_dec*2;
     if v[j]='1' then v_dec:=v_dec+1;
   end;
   writeln('v_dec=',v_dec);
   writeln;

   //m0_dec=(v_dec-x0_dec)^d mod N
   m0_dec:=(v_dec-x0_dec); if m0_dec<0 then m0_dec:=m0_dec+n;
   tmp:=m0_dec;
   for j:=2 to d do m0_dec:=(m0_dec*tmp) mod n;
   writeln('m0_dec=(v_dec-x0_dec)^d mod N=',m0_dec);

   //m1_dec=(v_dec-x1_dec)^d mod N
   m1_dec:=(v_dec-x1_dec); if m1_dec<0 then m1_dec:=m1_dec+n;
   tmp:=m1_dec;
   for j:=2 to d do m1_dec:=(m1_dec*tmp) mod n;
   writeln('m1_dec=(v_dec-x1_dec)^d mod N=',m1_dec);
   writeln;

   //обрабатываем сообщение s0
   writeln('coding of message S0');
   //расчет числа блоков
   s:=s0;
   blocks_num:=length(s) div block_size;
   c:='';
   for i:=1 to blocks_num do
   begin
      //вырезаем блок из выровненного бинарного кода s0
      ss:=''; for j:=1 to block_size do ss:=ss+s[(i-1)*block_size+j];
      //переводим блок из текстового (бинарного) в числовой формат
      s_dec:=0;
      for j:=1 to block_size do
      begin
         s_dec:=s_dec*2;
         if ss[j]='1' then s_dec:=s_dec+1;
      end;
      //вычисляем окончательный код блока из s0
      c_dec:=(s_dec+m0_dec) mod n;
      //перевод c_dec из числового в текстовый (бинарный) формат
      cc:=''; tmp:=c_dec;
      for j:=1 to block_size+1 do
      begin
         if (tmp mod 2)=1 then cc:='1'+cc else cc:='0'+cc;
         tmp:=tmp div 2;
      end;
      //наращивание окончательного ответа
      c:=c+cc;
      //печать промежуточного результата
      writeln('block',i:3,': s=',ss,'=',s_dec:4,' ==> ',cc,'=',c_dec:4);
   end;
   writeln('===========================');
   write('oblivious transfer message S0: m0= ');
   for i:=1 to length(c) do
   begin
      write(c[i]);
      if (i mod (block_size+1))=0 then write(' ');
   end;
   writeln; writeln;

   writeln('coding of message S1');
   //обрабатываем сообщение s1
   //расчет числа блоков
   s:=s1;
   blocks_num:=length(s1) div block_size;
   c:='';
   for i:=1 to blocks_num do
   begin
      //вырезаем блок из выровненного бинарного кода s0
      ss:=''; for j:=1 to block_size do ss:=ss+s[(i-1)*block_size+j];
      //переводим блок из текстового (бинарного) в числовой формат
      s_dec:=0;
      for j:=1 to block_size do
      begin
         s_dec:=s_dec*2;
         if ss[j]='1' then s_dec:=s_dec+1;
      end;
      //вычисляем окончательный код блока из s1
      c_dec:=(s_dec+m1_dec) mod n;
      //перевод c_dec из числового в текстовый (бинарный) формат
      cc:=''; tmp:=c_dec;
      for j:=1 to block_size+1 do
      begin
         if (tmp mod 2)=1 then cc:='1'+cc else cc:='0'+cc;
         tmp:=tmp div 2;
      end;
      //наращивание окончательного ответа
      c:=c+cc;
      //печать промежуточного результата
      writeln('block',i:3,': s=',ss,'=',s_dec:4,' ==> ',cc,'=',c_dec:4);
   end;
   writeln('===========================');
   write('oblivious transfer message S1: m1= ');
   for i:=1 to length(c) do
   begin
      write(c[i]);
      if (i mod (block_size+1))=0 then write(' ');
   end;
   writeln;
end.
