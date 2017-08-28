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

//учебный шаблон клиента забывчивого протокола передачи сообщений

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

program oblivious_client;
var
   n,e:integer; //ключи RSA, полученные от сервера
   b:integer; //секретный выбор клиента
   s,ss:string; //входной (от сервера) битовый вектор и его блок
   c,cc:string; //выходной (декодированный) битовый вектор и его блок
   m0,m1:string; //сообщения, полученные от сервера
   x0,x1:string; //числа шага 2 от сервера в текстовом (бинарном) формате
   k:string; //секретное число шага 4 протокола
   v:string; //результат шага 5 для сервера в текстовой (битовой) форме
   x0_dec,x1_dec,s_dec,c_dec,v_dec,k_dec:integer; //вспомогательные переменные
   i,j,block_size,blocks_num,tmp:integer; //вспомогательные переменные
begin
   //ввод исходных данных
   writeln('Oblivious transfer client');
   writeln('n,e - RSA keys (numbers)');
   writeln('m0,m1 - text messages (binary codes)');
   //ввод ключей RSA
   write('n='); readln(n);
   write('e='); readln(e);
   //вычисление размера блока
   block_size:=0; tmp:=1;
   while tmp<n do begin tmp:=tmp*2; block_size:=block_size+1; end;
   writeln('message from server block size=',block_size);
   writeln('output message block size=',block_size-1);
   writeln;
   
   write('waiting from server: x0='); readln(x0);
   //перевод x0 в числовой формат
   x0_dec:=0;
   for j:=1 to length(x0) do
   begin
      x0_dec:=x0_dec*2;
      if x0[j]='1' then x0_dec:=x0_dec+1;
   end;
   writeln('x0=',x0_dec); writeln;
   
   write('waiting from server: x1='); readln(x1);
   //перевод x0 в числовой формат
   x1_dec:=0;
   for j:=1 to length(x1) do
   begin
      x1_dec:=x1_dec*2;
      if x1[j]='1' then x1_dec:=x1_dec+1;
   end;
   writeln('x1=',x1_dec); writeln;
   
   //------------------------------------------------------
   //шаг 3 протокола (секретный выбор клиентом номера сообщения на сервере)
   //------------------------------------------------------
   write('select message on server (s0 - 0, s1 - 1): b='); readln(b);

   //------------------------------------------------------
   //шаг 4 протокола (генерация клиентом секретного числа k)
   //------------------------------------------------------
   randomize;
   //генерация k на 1 бит меньше размера блока
   k:=''; k_dec:=0;
   for j:=1 to block_size-1 do
     if random(2)=1 then begin k:=k+'1'; k_dec:=k_dec*2+1; end
                    else begin k:=k+'0'; k_dec:=k_dec*2; end;
   writeln('secret number: k=',k_dec,'=',k);
   
   //------------------------------------------------------
   //шаг 5 протокола (расчет и публикация клиентом числа v=(x_b+k^e) mod N)
   //------------------------------------------------------
   tmp:=1; for j:=1 to e do tmp:=(tmp*k_dec) mod n;
   if b=0 then v_dec:=(x0_dec+tmp) mod n;
   if b=1 then v_dec:=(x1_dec+tmp) mod n;
   //перевод v из числового в текстовый (бинарный) формат
   v:=''; tmp:=v_dec;
   while tmp>0 do
   begin
      if (tmp mod 2)=1 then v:='1'+v else v:='0'+v;
      tmp:=tmp div 2;
   end;
   writeln('v=',v_dec,'= ',v);

   //------------------------------------------------------
   //шаг 7 протокола (декодирование выбранного сообщения)
   //------------------------------------------------------
   repeat
   write('waiting from server: m0='); readln(m0);
   write('waiting from server: m1='); readln(m1);
   if length(m0)<>length(m1) then writeln('ERROR: length(m0)<>length(m1)');
   until length(m0)=length(m1);

   if b=0 then s:=m0;
   if b=1 then s:=m1;
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
      //вычисляем окончательный код блока
      c_dec:=(s_dec-k_dec) mod n; if c_dec<0 then c_dec:=c_dec+n;
      //перевод c_dec из числового в текстовый (бинарный) формат
      //(размер выходного блока на 1 бит меньше)
      cc:=''; tmp:=c_dec;
      for j:=1 to block_size-1 do
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
   writeln('message: ',c);
end.
