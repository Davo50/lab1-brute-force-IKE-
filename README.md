# README — Лабораторная работа: восстановление пароля для IKEv1 Aggressive

У нас есть `gen.py`, который генерирует «тестовые задания» для IKEv1 (Aggressive) — фиксирует все параметры сессии **кроме пароля** и выдаёт данные в виде строки hex-полей, разделённых символом `*`. Задача — реализовать `crack` для перебора паролей по маске и восстановления пароля, вычисляя соответствующие HMAC'ы и сравнивая с HASH из задания.

Ниже — подробное описание констант, формата файла, алгоритма и примеры из консоли.

---

# 1. Константы

Эти поля жёстко зашиты в `gen.py`:

* `Ci`:

  ```
  a0613ec7445c462a13f6ffbba65085fe
  ```
* `Ni`:

  ```
  9ad2da7c2b87fe3b4dfcc422d35ea86e7cedadebc653e58df84d0e55ffd51b72
  ```
* `g_x`:

  ```
  ee75ea8fbe83f87fde2d83700a9c6f6808af36f84147babd38dccf1000f7d82f433bd6f49d1a4d974a8c2f2537bcf5cf9d8732c22da7da98650895585276c317ebdcab2f1049843c22519f1f107a3b99005e428a9517c299cf373e3438d31358e222f2a9e150cc3da9d50090f4c4d2800a07680de75c1ef5a3096079b56d78c0
  ```
* `Cr`:

  ```
  baf00945c9f5796ca2ebe3c8e492b4b4
  ```
* `Nr`:

  ```
  6476695c1cc3cc35f641c924faa57696804e809f4101b618426ca10c7edd41a3
  ```
* `g_y`:

  ```
  2478d31ad28bce3f62a30dfe8209f61ce1939894c33978bcee7768fe7e0218b2e8123a389c5647bdf242495baf8862ef19693b9f5c32b33ae9d1a4c2f29ec92554ab4bcc58653b10956a277dd78661b14006abd63e334e186e7db7d1f39ac2427c32200c9d36bc8dd7ac2a3364d6c13ff7b6a2086961f0048ae7ae919d624520
  ```
* `SAi`:

  ```
  2cc74410c9e829d3d9c1f02190140372
  ```
* `IDr`:

  ```
  3e6ce2b75b609e9295946bdf8e8569a4
  ```
* `HASH` (пример):

  ```
  6711fab905453ab664c9ebe1dbe135b329f4f0ef
  ```

---

# 2. Формат выходного файла

Строка имеет формат (поля в указанном порядке, hex, разделитель `*`):

```
Ni*Nr*g_x*g_y*Ci*Cr*SAi*IDr*HASH
```

Пример (одна строка — все поля через `*`):

```
9ad2...b72*6476...1a3*ee75...8c0*2478...4520*a061...85fe*baf0...4b4*2cc7...0372*3e6c...69a4*3df7...ab8
```

---

# 3. Как `gen.py` формирует HASH

1. `DATA1 = Ni || Nr` (конкатенация байтов Ni и Nr).
2. `skeyid = HMAC_hash(key = password_bytes, message = DATA1)` — то есть пароль используется как **ключ** HMAC.
3. `DATA2 = g_y || g_x || Cr || Ci || SAi || IDr`.
4. `HASH = HMAC_hash(key = skeyid, message = DATA2)`.

В `gen.py` алгоритм (md5/sha1/sha256/...) выбирается аргументом `-m` и применяется и для `skeyid`, и для `HASH`. В реализации `crack.*` мы детектируем алгоритм по длине `HASH` (см. §4).

---

# 4. Определение алгоритма по длине хеша

Программа автоматически определяет хэш-алгоритм по длине `HASH` (в байтах):

* 16 bytes → `md5`
* 20 bytes → `sha1`
* 32 bytes → `sha256`
* 48 bytes → `sha384`
* 64 bytes → `sha512`

Если длина нетипична — можно добавить опцию принудительного указания алгоритма.

---

# 5. Маски для перебора пароля

Маска задаётся строкой, где каждый символ определяет алфавит для соответствующей позиции (слева направо):

* `a` — все латинские символы **малые + заглавные** и **цифры** (`a-zA-Z0-9`)
* `d` — только цифры (`0-9`)
* `l` — только маленькие латинские (`a-z`)
* `u` — только заглавные латинские (`A-Z`)

Примеры:

* `aaadd` — первые 2 символа из `a`, следующие 2 — `a`, последние 2 — `d` (в сумме длина маски = длина пароля).
* `aaa` — перебор `a-zA-Z0-9` на 3 позициях.

---

# 6. Запуск и примеры

## Генерация тестового задания

Примеры запусков `gen.py` (в твоём окружении):

```bash
(.venv) davidmuradan@MacBook-Pro-9 lab1 % python3 gen.py -m md5 -p Svo
9ad2da7c2b87fe3b4dfcc422d35ea86e7cedadebc653e58df84d0e55ffd51b72*6476695c1cc3cc35f641c924faa57696804e809f4101b618426ca10c7edd41a3*ee75ea8fbe83f87fde2d83700a9c6f6808af36f84147babd38dccf1000f7d82f433bd6f49d1a4d974a8c2f2537bcf5cf9d8732c22da7da98650895585276c317ebdcab2f1049843c22519f1f107a3b99005e428a9517c299cf373e3438d31358e222f2a9e150cc3da9d50090f4c4d2800a07680de75c1ef5a3096079b56d78c0*2478d31ad28bce3f62a30dfe8209f61ce1939894c33978bcee7768fe7e0218b2e8123a389c5647bdf242495baf8862ef19693b9f5c32b33ae9d1a4c2f29ec92554ab4bcc58653b10956a277dd78661b14006abd63e334e186e7db7d1f39ac2427c32200c9d36bc8dd7ac2a3364d6c13ff7b6a2086961f0048ae7ae919d624520*a0613ec7445c462a13f6ffbba65085fe*baf00945c9f5796ca2ebe3c8e492b4b4*2cc74410c9e829d3d9c1f02190140372*3e6ce2b75b609e9295946bdf8e8569a4*3df73943e21ffac438e4f6c08e700ab8
```

(строка может быть записана в `test.txt` в UTF-16 — `gen.py` в примерах так делает).

## Пример запуска `crack` (Go-бинарник, собранный из `crack.go`)

```bash
(.venv) davidmuradan@MacBook-Pro-9 lab1 % ./crack -m aaa test.txt

Detected hash: md5 (16 bytes)
Mask: aaa -> positions: 3, total combinations: 238328

FOUND password: Svo
Attempts: 170453, elapsed: 0s, speed: 586006 tries/s
```

## Примеры работы `gen.py` (другие пароли) и поиск с `crack`:

```bash
(.venv) davidmuradan@MacBook-Pro-9 lab1 % python3 gen.py -m md5 -p 12345
...*...*...*...*...*...*...*...*15f1e96333343e4728cacdceb4080e68

(.venv) davidmuradan@MacBook-Pro-9 lab1 % python3 gen.py -m md5 -p Dav111
...*...*...*...*...*...*...*...*c1c7079a8ef758479cb1bd63cf4d00d5

(.venv) davidmuradan@MacBook-Pro-9 lab1 % python3 gen.py -m md5 -p 123456
...*...*...*...*...*...*...*...*8d91a26c2935b45398140e19a2251eb5

(.venv) davidmuradan@MacBook-Pro-9 lab1 % python3 gen.py -m md5 -p Svo22
...*...*...*...*...*...*...*...*656ba355d0e1f9d65379452a0ec4c133

(.venv) davidmuradan@MacBook-Pro-9 lab1 % ./crack -m ulldd test.txt

Detected hash: md5 (16 bytes)
Mask: ulldd -> positions: 5, total combinations: 1757600
Tried: 1230755 / 1757600 (70.024750%), speed: 615067 tries/s, elapsed: 2s, current: Sfj55

FOUND password: Svo22
Attempts: 1272823, elapsed: 2s, speed: 614858 tries/s
```

Еще примеры:

```bash
(.venv) davidmuradan@MacBook-Pro-9 lab1 % python3 gen.py -m md5 -p Davo 
9ad2da7c2b87fe3b4dfcc422d35ea86e7cedadebc653e58df84d0e55ffd51b72*6476695c1cc3cc35f641c924faa57696804e809f4101b618426ca10c7edd41a3*ee75ea8fbe83f87fde2d83700a9c6f6808af36f84147babd38dccf1000f7d82f433bd6f49d1a4d974a8c2f2537bcf5cf9d8732c22da7da98650895585276c317ebdcab2f1049843c22519f1f107a3b99005e428a9517c299cf373e3438d31358e222f2a9e150cc3da9d50090f4c4d2800a07680de75c1ef5a3096079b56d78c0*2478d31ad28bce3f62a30dfe8209f61ce1939894c33978bcee7768fe7e0218b2e8123a389c5647bdf242495baf8862ef19693b9f5c32b33ae9d1a4c2f29ec92554ab4bcc58653b10956a277dd78661b14006abd63e334e186e7db7d1f39ac2427c32200c9d36bc8dd7ac2a3364d6c13ff7b6a2086961f0048ae7ae919d624520*a0613ec7445c462a13f6ffbba65085fe*baf00945c9f5796ca2ebe3c8e492b4b4*2cc74410c9e829d3d9c1f02190140372*3e6ce2b75b609e9295946bdf8e8569a4*375a6aed49e308d50423a259b45b11cc
(.venv) davidmuradan@MacBook-Pro-9 lab1 % ./crack -m aaaa test.txt

Detected hash: md5 (16 bytes)
Mask: aaaa -> positions: 4, total combinations: 14776336
Tried: 1225041 / 14776336 (8.290560%), speed: 612374 tries/s, elapsed: 2s, current: fiQT
Tried: 2465402 / 14776336 (16.684799%), speed: 616192 tries/s, elapsed: 4s, current: kvwI
Tried: 3705010 / 14776336 (25.073943%), speed: 617396 tries/s, elapsed: 6s, current: pH0o
Tried: 4937791 / 14776336 (33.416884%), speed: 617145 tries/s, elapsed: 8s, current: uSHX
Tried: 6170652 / 14776336 (41.760366%), speed: 617002 tries/s, elapsed: 10s, current: z3qO

FOUND password: Davo
Attempts: 6912829, elapsed: 11s, speed: 617101 tries/s
```

# 7. Технические детали реализации

* `skeyid = HMAC_hash(key=password_bytes, message = Ni || Nr)`.
* `HASH = HMAC_hash(key=skeyid, message = g_y || g_x || Cr || Ci || SAi || IDr)`.
* В обоих шагов используется один и тот же hash-функционал (определенный по длине HASH или заданный явно).
* Алгоритм перебора реализован как «одометр» (индексы по позициям маски), что экономит память и позволяет легко добавить распределение по потокам/процессам.
* `gen.py` выводит hex-поля в указанном порядке; `crack` ожидает именно этот порядок.
