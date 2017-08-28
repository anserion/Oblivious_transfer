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

//учебный шаблон создания пары ключей RSA

program RSA_weak_keys;

//расширенный алгоритм Евклида
function gcdex(a,b:integer; var x,y:integer):integer;
var x1,y1,d:integer;
begin
   if a=0 then 
   begin
      x:=0; y:=1;
      gcdex:=b;
   end else
   begin
      d:=gcdex(b mod a, a, x1, y1);
      x:=y1-(b div a)*x1;
      y:=x1;
      gcdex:=d;
   end;
end;

var 
   p,q:integer; //компоненты секрета RSA
   n,e,d:integer; //(n,e) - публичный ключ, (n,d) - секретный ключ
   i,j,phi_n,gcd_phi_e,tmp,n_size:integer; //вспомогательные переменные
   primes:array[1..100] of integer; //массив простых чисел для удобства выбора P и Q
   primes_num:integer;
   flag:boolean;
begin
   //генерация простых чисел из диапазона (2..127);
   primes[1]:=2; primes_num:=1;
   for i:=3 to 127 do
   begin
      flag:=true;
      for j:=1 to primes_num do
         if (i mod primes[j])=0 then flag:=false;
      if flag then
      begin
         primes_num:=primes_num+1;
         primes[primes_num]:=i;
      end;
   end;
   
   //ввод исходных данных
   writeln('RSA weak pair generate');
   writeln('enter primes P and Q from table (except 2)');
   //печать таблицы простых чисел
   for i:=1 to primes_num do
   begin
      write(primes[i]:4);
      if (i mod 10)=0 then writeln;
   end;
   writeln;
   //ввод первой компоненты секрета RSA
   repeat
      write('P='); readln(p);
      flag:=false; 
      for i:=2 to primes_num do
         if primes[i]=p then flag:=true;
      if flag=false then writeln('no');
   until flag;
   //ввод второй компоненты секрета RSA
   repeat
      write('Q='); readln(q);
      flag:=false; 
      for i:=2 to primes_num do
         if primes[i]=q then flag:=true;
      if flag=false then writeln('no');
   until flag;
   
   //шаг 1: вычисляем n=p*q
   n:=p*q;
   //вычисляем размер n в битах
   n_size:=0; tmp:=1; while tmp<n do begin tmp:=tmp*2; n_size:=n_size+1; end;
   
   //шаг 2: находим функцию Эйлера phi(n)
   phi_n:=(p-1)*(q-1);
   //печатаем значение функции Эйлера
   writeln('phi(P*Q)=',phi_n);
   
   //генерация случайного публичного ключа
   randomize;
   repeat
      //шаг 3: выбираем небольшое нечетное "e", взаимно простое с phi(n)
      e:=(random((n div 2)-1)+1)*2+1;
      //dd = НОД(e,phi(n)) по расширенному алгоритму Евклида
      //т.е. dd = e*d + phi_n*tmp = 1
      gcd_phi_e:=gcdex(e,phi_n,d,tmp);
   until gcd_phi_e=1;
   //шаг 4: вычисляем d=inv(e) mod phi(n) методом, основанным на
   //расширенном алгоритме Евклида (с поправкой на возможное
   //отрицательное значение d, полученное функцией gcdex)
   d:=((d mod phi_n)+phi_n) mod phi_n;
   writeln('=========================');
   writeln('auto generation mode');
   writeln('n=P*Q=',n,' (',n_size,' bits)');
   writeln('open key: e=',e);
   writeln('private key: d=',d);
   
   //ручной ввод публичного ключа
   writeln('=========================');
   writeln('manual generation mode');
   repeat
      write('e='); readln(e);
      gcd_phi_e:=gcdex(e,phi_n,d,tmp);
      if gcd_phi_e<>1 then writeln('gcd(',phi_n,',',e,')<>1');
   until gcd_phi_e=1;
   d:=((d mod phi_n)+phi_n) mod phi_n;
   //печать результата расчетов
   writeln('=========================');
   writeln('n=P*Q=',n,' (',n_size,' bits)');
   writeln('open key: e=',e);
   writeln('private key: d=',d);
end.
