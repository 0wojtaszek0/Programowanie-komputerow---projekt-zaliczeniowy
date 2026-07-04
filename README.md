# Dokumentacja techniczna — Menedżer Haseł (`password_manager.py`)

Dokument opisuje architekturę i implementację lokalnego menedżera haseł napisanego w Pythonie z użyciem biblioteki `customtkinter` (GUI), `sqlite3` (baza danych) oraz `cryptography` (kryptografia). Skupia się nie tylko na tym, **co** kod robi, ale przede wszystkim na tym, **dlaczego** poszczególne rozwiązania zostały wybrane — w kontekście cyberbezpieczeństwa, entropii, atomowości operacji i użyteczności.

## 0. Instalacja i uruchomienie

```bash
pip install -r requirements.txt
python3 password_manager.py
```

`requirements.txt` zawiera trzy zależności runtime'owe: `customtkinter` (GUI),
`pyperclip` (schowek systemowy) i `cryptography` (PBKDF2/Fernet). `sqlite3`,
`tkinter` i `secrets` są częścią standardowej biblioteki Pythona.

---

## 1. Ogólna architektura

Aplikacja składa się z trzech głównych klas, świadomie rozdzielonych zgodnie z zasadą pojedynczej odpowiedzialności (Single Responsibility Principle):

| Klasa | Odpowiedzialność |
|-------|------------------|
| `DatabaseManager` | Warstwa dostępu do danych (SQLite): tworzenie schematu, CRUD na hasłach, ustawieniach i użytkowniku. |
| `CryptoManager` | Warstwa kryptograficzna: derywacja klucza z hasła głównego, szyfrowanie/odszyfrowywanie wpisów, haszowanie hasła głównego. |
| `PasswordManagerApp` | Warstwa prezentacji (GUI) i kontroler łączący pozostałe warstwy. |

### Dlaczego taki podział?

- **Testowalność** — logikę kryptograficzną i bazodanową można testować w izolacji, bez uruchamiania GUI.
- **Bezpieczeństwo** — cały „wrażliwy” kod jest w jednym miejscu (`CryptoManager`), łatwiej go audytować.
- **Wymiana implementacji** — teoretycznie SQLite można podmienić na inny backend, a Fernet na inny algorytm, bez ruszania GUI.

---

## 2. Warstwa bazodanowa — `DatabaseManager`

### 2.1. Schemat bazy

Baza SQLite zawiera trzy tabele:

```sql
users     (id, master_hash, salt)
passwords (id, website, username, encrypted_password BLOB, notes, modified_at)
settings  (key PRIMARY KEY, value)
```

**Dlaczego SQLite?**
- Zero konfiguracji, wszystko trzymamy w jednym pliku `.db`, który użytkownik może łatwo przenieść na inny komputer albo zbackupować.
- Aplikacja jest lokalna, jednoużytkownikowa — nie potrzebujemy serwera bazy danych, poola połączeń ani replikacji.
- Wbudowana obsługa transakcji (potrzebna przy zmianie hasła głównego, gdzie re-szyfrujemy wszystkie wpisy — patrz sekcja 4.5).

**Dlaczego `encrypted_password` to `BLOB`, a nie `TEXT`?**
Fernet zwraca zaszyfrowany token jako `bytes` (Base64-encoded, ale wewnątrz bibliotek trzymany jako surowe bajty). Zapisując go jako `BLOB` unikamy niepotrzebnej konwersji do stringa i z powrotem — mniej okazji, żeby coś zniekształcić kodowaniem.

**Dlaczego `row_factory = sqlite3.Row`?**
Pozwala odwoływać się do kolumn po nazwie (`row["website"]`) zamiast po indeksie (`row[1]`) — kod jest odporny na zmianę kolejności kolumn i czytelniejszy.

### 2.2. Zapytania parametryzowane

Wszystkie operacje na bazie używają placeholderów `?`:

```python
cursor.execute("INSERT INTO passwords (...) VALUES (?, ?, ?, ?, ?)", (website, username, ...))
```

**Dlaczego to jest krytyczne z punktu widzenia bezpieczeństwa?**
Chroni przed **SQL Injection**. Gdyby użytkownik wpisał w polu „Serwis” coś w rodzaju `foo'); DROP TABLE passwords;--`, przy konkatenacji stringów zniszczyłoby to bazę. Placeholder przekazuje wartość jako parametr, nie jako fragment SQL — driver SQLite dba o poprawne escapowanie.

### 2.3. Ustawienia — wzorzec key/value

Tabela `settings` używa wzorca klucz/wartość zamiast osobnych kolumn dla każdego ustawienia. Zapis odbywa się przez UPSERT:

```sql
INSERT INTO settings (key, value) VALUES (?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value
```

**Dlaczego?**
- Dodanie nowego ustawienia nie wymaga migracji schematu.
- `ON CONFLICT ... DO UPDATE` (upsert) załatwia jednym zapytaniem to, co inaczej wymagałoby `SELECT`, warunku i `INSERT` albo `UPDATE`.

---

## 3. Warstwa kryptograficzna — `CryptoManager`

To najważniejsza część aplikacji z punktu widzenia bezpieczeństwa. Poniżej omawiam każdą kluczową decyzję.

### 3.1. Sól — `generate_salt`

```python
@staticmethod
def generate_salt(length: int = 16) -> bytes:
    return os.urandom(length)
```

**Dlaczego 16 bajtów?**
128 bitów entropii — standard branżowy (NIST SP 800-132 zaleca minimum 128 bitów soli). Prawdopodobieństwo kolizji przy 16-bajtowej soli jest znikome (paradoks urodzin: kolizja pojawi się średnio po ~2⁶⁴ próbach).

**Dlaczego `os.urandom`, a nie `random.random()`?**
`random` w Pythonie używa deterministycznego algorytmu Mersenne Twister — świetnego do symulacji, ale **kryptograficznie niebezpiecznego** (znając kilka wyjść, można przewidzieć następne). `os.urandom` czyta z bezpiecznego źródła losowości OS (`/dev/urandom` na Linux/macOS, `CryptGenRandom` na Windows), które jest zaprojektowane pod kątem kryptografii.

**Do czego w ogóle służy sól?**
- **Ochrona przed rainbow tables** — bez soli tabele prekomputowanych hashów typowych haseł pozwoliłyby atakującemu natychmiast złamać popularne hasła. Sól sprawia, że dla każdego użytkownika ten sam plaintext daje inny hash.
- **Ochrona przed atakami wsadowymi** — atakujący, który zdobył bazę, nie może testować jednego kandydata hasła przeciwko wielu użytkownikom naraz.

### 3.2. Derywacja klucza — PBKDF2HMAC-SHA256, 200 000 iteracji

```python
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=200_000,
    backend=default_backend(),
)
return base64.urlsafe_b64encode(kdf.derive(password))
```

**Dlaczego PBKDF2, a nie zwykły SHA-256?**
Zwykły hash jest błyskawiczny — GPU liczy miliardy SHA-256 na sekundę. Hasła użytkowników mają niską entropię (rzadko przekraczają 40–60 bitów), więc pojedyncze przejście przez SHA-256 = złamanie w minutach. PBKDF2 celowo *spowalnia* obliczenie, robiąc **200 000 iteracji HMAC-SHA256**. Atakującemu każde zgadnięcie hasła zajmuje 200 tys. razy więcej czasu.

**Dlaczego akurat 200 000 iteracji?**
- OWASP (aktualne rekomendacje na 2023+) zaleca minimum **600 000 iteracji dla PBKDF2-HMAC-SHA256**. Wartość 200 000 to kompromis użyteczności (aplikacja desktopowa musi zalogować użytkownika szybko — <1 s na przeciętnym CPU) i bezpieczeństwa.
- Wartość ta powinna być podnoszona wraz z rozwojem sprzętu. **W praktyce warto rozważyć zwiększenie do 600 000** albo migrację na `Argon2id` (patrz sekcja 6 „Możliwe usprawnienia”).

**Dlaczego długość klucza = 32 bajty?**
Fernet wymaga 256-bitowego klucza (dokładniej: 128 bitów na AES-128-CBC + 128 bitów na HMAC-SHA256 do autentykacji). 32 bajty × 8 = 256 bitów.

**Dlaczego `base64.urlsafe_b64encode` na wyjściu?**
Fernet oczekuje klucza w formacie URL-safe base64 — jest to wymaganie API biblioteki `cryptography`, nie związane z bezpieczeństwem.

### 3.3. Fernet do szyfrowania wpisów

```python
self.fernet = Fernet(self._derive_key(...))
...
def encrypt(self, plaintext: str) -> bytes:
    return self.fernet.encrypt(plaintext.encode("utf-8"))
```

**Co to jest Fernet?**
Symetryczny „high-level” schemat szyfrowania z biblioteki `cryptography`. Pod spodem:

1. **AES-128-CBC** — szyfr blokowy w trybie CBC do zapewnienia poufności.
2. **PKCS7 padding** — bo AES działa na blokach 16-bajtowych.
3. **HMAC-SHA256** — autentykacja treści (chroni przed manipulacją zaszyfrowanym tekstem).
4. **Losowy IV** dla każdego wywołania `encrypt` — ten sam plaintext szyfrowany dwa razy daje różne wyjścia (semantyczna bezpieczność).
5. **Timestamp** — pozwala na wygaszanie tokenów (u nas nieużywane, ale nie przeszkadza).

**Dlaczego Fernet, a nie samo AES?**
- **Autentykacja** — najczęstszy błąd amatorów kryptografii to szyfrowanie bez MAC. Bez HMAC atakujący, który ma dostęp do bazy, może modyfikować szyfrogramy (np. bit-flip) tak, że po odszyfrowaniu wyjdzie inny, wybrany przez niego tekst. Fernet to eliminuje.
- **Losowy IV** — Fernet sam generuje kryptograficznie bezpieczny IV, więc nie da się popełnić błędu polegającego na powtórzeniu tego samego IV (co przy CBC prowadzi do wycieku informacji).
- **Zero „nogi na stopie”** — Fernet nie daje wielu opcji do wyboru, więc trudno użyć go źle. To zgodne z zasadą „bezpieczne domyślne wartości” (secure by default).

### 3.4. Haszowanie hasła głównego

```python
@staticmethod
def hash_password(password: str, salt: bytes) -> str:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000, ...)
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8"))).decode("utf-8")
```

Hash hasła głównego trafia do tabeli `users`. Przy logowaniu porównujemy `hash_password(input, salt) == stored_hash`.

**Uwaga na przyszłość:** porównanie stringów przez `==` w Pythonie **nie jest** ochronione przed atakami czasowymi (timing attack). Dla aplikacji lokalnej ryzyko jest znikome (atakujący z dostępem do procesu ma i tak wszystko), ale w wersji sieciowej należałoby użyć `hmac.compare_digest`.

**Dlaczego derywacja klucza i haszowanie hasła używają tej samej funkcji?**
Bo w istocie robią to samo — biorą hasło, sól, iteracje i wyprowadzają 256-bitową wartość. To upraszcza kod i redukuje powierzchnię ataku. Ważne: **hash zapisany w `users.master_hash` NIE jest kluczem szyfrującym.** Klucz jest wyprowadzany dokładnie tak samo, ale trzymany tylko w pamięci procesu (`self.crypto_manager.fernet`), nigdy nie zapisywany na dysk.

---

## 4. Warstwa aplikacyjna — `PasswordManagerApp`

### 4.1. Ekran logowania i rejestracji

Aplikacja przy starcie sprawdza, czy w bazie istnieje wpis w tabeli `users`. Jeśli nie — pokazuje formularz rejestracji. Jeśli tak — formularz logowania. To eliminuje potrzebę osobnej „instalacji”: pierwszy uruchomienie *jest* rejestracją.

Rejestracja:
1. Wygeneruj losową sól (`os.urandom(16)`).
2. Wylicz `hash_password(master, salt)`.
3. Zapisz sól (Base64-encoded, jako TEXT) i hash w tabeli `users`.

Logowanie:
1. Wczytaj sól i hash z bazy.
2. Wylicz hash z podanego hasła i tej samej soli.
3. Porównaj z zapisanym hashem — jeśli zgadza się, zbuduj `CryptoManager` (klucz Fernet zostaje w pamięci).

### 4.2. Timer bezczynności

```python
def _bind_activity_events(self):
    self.bind_all("<KeyPress>", self._reset_inactivity_timer)
    self.bind_all("<Button-1>", self._reset_inactivity_timer)
```

**Dlaczego bez `<Motion>`?**
Ruch myszy odpalałby callback dziesiątki razy na sekundę — każda przeplanowana promocja `after_cancel` + `after` to niepotrzebny narzut. Klawiatura i kliknięcia to i tak realne „interakcje użytkownika”. Komentarz w kodzie przy `_bind_activity_events` wprost to wyjaśnia.

**Dlaczego auto-blokada po bezczynności jest w ogóle potrzebna?**
- Ochrona przed **shoulder surfing** (ktoś zajrzał do niepilnowanej sesji).
- Redukcja okna czasowego, w którym pamięć procesu zawiera odszyfrowane hasła (i zaimportowany klucz Fernet).

Po zablokowaniu: `self.crypto_manager = None` — najważniejsza obiektowa referencja do klucza znika. Sam klucz może jeszcze *chwilowo* leżeć w pamięci, dopóki GC go nie zebrał; Python nie daje nam gwarancji „wyzeruj bajty w pamięci” (jak `SecureString` w .NET), więc to najlepsze, co możemy zrobić bez schodzenia do `ctypes`.

### 4.3. Schowek z automatycznym czyszczeniem

```python
pyperclip.copy(password)
self.after(self.clipboard_timeout * 1000, self._clear_clipboard)
```

Skopiowane hasło trafia do systemowego schowka na (domyślnie) 20 sekund, potem schowek jest czyszczony (`pyperclip.copy("")`).

**Dlaczego to jest bardzo ważne?**
Schowek to jedno z najbardziej nieszczelnych miejsc w OS:
- Historia schowka (Windows 10+, macOS ClipboardManagerów) potrafi zapamiętać wiele wpisów.
- Aplikacje w tle (menedżery schowka, komunikatory) mogą odczytywać schowek bez pytania.
- Wklejenie przez pomyłkę do niewłaściwego okna = wyciek do logów.

Krótki timeout znacząco ogranicza ekspozycję.

**Uwaga na subtelny szczegół (`_copy_password`):**
```python
self.after(self.clipboard_timeout * 1000, self._clear_clipboard)
messagebox.showinfo("Sukces", msg)
```

Timer jest odpalany **przed** modalnym oknem informacyjnym. Gdyby było odwrotnie, `messagebox` (który blokuje) opóźniałby start odliczania o czas, w którym użytkownik ma otwarte okno — czyli hasło leżałoby w schowku znacznie dłużej niż deklarowane 20 sekund. Komentarz w kodzie sygnalizuje tę zależność.

### 4.4. Generator haseł — `_fill_generated_password`

```python
password = [secrets.choice(pool) for pool in required]
while len(password) < length:
    password.append(secrets.choice(chars))
secrets.SystemRandom().shuffle(password)
```

**Cztery niezależne kategorie znaków.** Użytkownik zaznacza checkboxami, z jakich
puli ma korzystać generator: małe litery, wielkie litery, cyfry, znaki specjalne.
Każda kategoria jest równoprawna — łącznie z małymi literami, które w
poprzedniej wersji były dodawane bezwarunkowo (bez możliwości wyłączenia) i
przez to warunek `if not chars: ...` (ostrzegający o braku wybranej kategorii)
był w praktyce nieosiągalny. Teraz `chars` może być puste, jeśli użytkownik
odznaczy wszystkie kategorie, więc walidacja rzeczywiście działa.

**Dlaczego `secrets`, a nie `random`?**
Ten sam powód co przy soli — `random` używa deterministycznego PRNG (Mersenne Twister), który znając kilka wygenerowanych haseł pozwoliłby przewidzieć następne. Moduł `secrets` (od Pythona 3.6) jest kryptograficznym opakowaniem `os.urandom` — jest **jedyną poprawną opcją** do generowania sekretów w Pythonie.

**Dlaczego najpierw dodajemy po jednym znaku z każdej wymaganej kategorii?**
Jeśli użytkownik zaznaczył „cyfry” i „znaki specjalne”, ma prawo oczekiwać, że wynik **na pewno** zawiera cyfrę i znak specjalny. Losując tylko ze zbiorczej puli, mielibyśmy pech: hasło o długości 8 z puli 90 znaków, którego rozkład akurat nie trafił w żadną cyfrę, byłoby zgodne z ustawieniami *statystycznie*, ale nie *ściśle*.

**Dlaczego potem `shuffle`?**
Bo bez tego pierwsze N znaków hasła (gdzie N to liczba kategorii) byłoby zawsze w kolejności „mała litera, duża litera, cyfra, znak specjalny” — atakujący, znając ustawienia generatora, mógłby wyeksploatować tę regularność. Shuffle likwiduje przewidywalny wzorzec.

**Dlaczego `length = max(8, len(required), int(length_var.get()))`?**
Trzy zabezpieczenia:
1. Minimum 8 znaków (bo krótsze hasła są trywialne do złamania nawet dla bcrypt).
2. Minimum tyle znaków, ile mamy wymaganych kategorii (inaczej nie zmieściłyby się wszystkie gwarantowane znaki).
3. To, co użytkownik ustawił suwakiem.

Komentarz w kodzie przy `_fill_generated_password` wprost to wyjaśnia.

### 4.5. Zmiana hasła głównego — operacja atomowa

To najbardziej złożona operacja w aplikacji:

```python
try:
    reencrypted = []
    for row in self.db.get_passwords():
        plaintext = old_crypto.decrypt(row["encrypted_password"])
        encrypted = new_crypto.encrypt(plaintext)
        reencrypted.append((row["id"], encrypted))

    cursor.execute("BEGIN")
    try:
        for password_id, encrypted in reencrypted:
            cursor.execute("UPDATE passwords SET encrypted_password = ? WHERE id = ?", ...)
        cursor.execute("UPDATE users SET master_hash = ?, salt = ?", ...)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
```

**Dlaczego to musi być atomowe?**
Nowe hasło główne = nowy klucz Fernet. Wszystkie istniejące szyfrogramy trzeba odszyfrować starym kluczem i zaszyfrować nowym. Jeśli w połowie procesu coś padnie (crash procesu, brak zasilania), połowa wpisów byłaby zaszyfrowana starym, połowa nowym — a jednocześnie zmienił się `master_hash`. Po restarcie użytkownik nie odszyfrowałby **niczego**. To bezpowrotna utrata danych.

**Jak to jest rozwiązane?**
1. **Faza przygotowania (poza transakcją):** przechodzimy przez wszystkie wpisy, odszyfrowujemy starym i szyfrujemy nowym kluczem, wynik trzymamy w liście `reencrypted` w pamięci. Jeśli tu coś się wywali (np. jeden wpis jest uszkodzony), *w ogóle* nie ruszamy bazy.
2. **Faza zapisu (transakcja):** `BEGIN` — potem hurtowo `UPDATE` wszystkich haseł + `UPDATE` na `users`. Jeśli cokolwiek zawiedzie — `ROLLBACK`.
3. **Commit** — dopiero po pomyślnym zapisie wszystkiego.

W efekcie użytkownik widzi jeden z dwóch stanów: „wszystko po staremu” albo „wszystko z nowym hasłem”. Nigdy nic pośredniego. Komentarz w kodzie przy `_change_master_password` wprost to podkreśla.

### 4.6. Przełączanie między bazami danych

Aplikacja pozwala trzymać wiele plików `.db`, każdy z własnym hasłem głównym. `_choose_existing_database` i `_create_new_database` używają natywnych dialogów systemowych (`filedialog`), które są bezpieczniejsze niż samodzielne wpisywanie ścieżek (mniej okazji na typo albo path traversal).

Metoda `_load_settings` *świadomie* nie wczytuje ostatnio używanej ścieżki z bazy — komentarz wyjaśnia, że to był martwy i ryzykowny mechanizm (mógł wywalić start aplikacji, jeśli ścieżka nie istnieje). Zawsze startujemy z domyślnym `passwords.db` w CWD.

---

## 5. Ocena siły hasła — `_calculate_password_strength`

Prosty heurystyczny scoring w skali 0–7:

- +1 za długość ≥ 8, ≥ 12, ≥ 16 (max +3 za długość — bo długość ma największy wpływ na entropię)
- +1 za obecność małych liter
- +1 za obecność wielkich liter
- +1 za obecność cyfr
- +1 za obecność znaków specjalnych

Wynik dzielony przez 7 → przedział [0, 1] → mapowany na etykiety „Bardzo słabe/Słabe/Średnie/Silne”.

**Dlaczego to nie jest matematycznie precyzyjna miara entropii?**
- Realna entropia zależy od tego, czy hasło jest wybrane losowo z jakiejś puli (wtedy `log2(rozmiar_puli^długość)`), czy jest to fraza w naturalnym języku (wtedy ~1 bit na znak — dużo mniej).
- Aplikacja nie zna źródła hasła — użytkownik może wpisać `P@ssw0rd`, które ma dobre „mieszanki” według scoringu, ale jest w każdej liście top-100 haseł.
- Dokładna miara wymagałaby użycia narzędzi typu **zxcvbn** (Dropbox), które sprawdza słowniki, sekwencje klawiatury itp.

**Dlaczego jednak taki uproszczony scoring wystarczy?**
Rolą paska siły w GUI jest głównie **feedback wizualny** — pchnąć użytkownika w kierunku dłuższego, bardziej zróżnicowanego hasła. Precyzja tu jest drugorzędna; ważne, że słabe hasła świecą na czerwono, a silne na zielono.

**Konkretne wartości i przybliżona entropia dla porównania:**

| Rodzaj hasła | Długość | Pula | Entropia (bity) | Czas łamania (offline, GPU) |
|--------------|---------|------|-----------------|------------------------------|
| Tylko małe litery | 8 | 26 | ~37 | godziny |
| a-z, A-Z, 0-9 | 8 | 62 | ~47 | dni |
| Wszystko | 12 | ~90 | ~78 | miliony lat |
| Wszystko | 16 | ~90 | ~104 | wieki |

Dlatego domyślna długość generatora to **16** — trafia w bezpieczny obszar nawet przy założeniu, że atakujący ma dużą moc obliczeniową.

---

## 6. Znane ograniczenia i możliwe usprawnienia

Dokument techniczny musi być uczciwy — kod ma świadome ograniczenia:

### 6.1. Iteracje PBKDF2
200 000 iteracji było dobrą wartością ~2018–2020. OWASP na 2024 zaleca ≥600 000. Podniesienie tej wartości wymagałoby migracji istniejących baz (przechowywać w bazie liczbę iteracji jako parametr, ewentualnie „rehashować” przy logowaniu).

### 6.2. PBKDF2 vs Argon2id
`Argon2id` (zwycięzca Password Hashing Competition, 2015) jest odporny na ataki GPU/ASIC dzięki wymaganiu dużej ilości pamięci na jedno hashowanie. Migracja wymagałaby tylko podmiany `PBKDF2HMAC` na `argon2-cffi` i zapisywania parametrów (memory cost, parallelism) w bazie.

### 6.3. Brak weryfikacji integralności bazy jako całości
Baza SQLite nie jest podpisana. Ktoś z dostępem do pliku może usuwać wpisy (choć nie odczytać ich zawartości). Można by dodać kolumnę HMAC-SHA256 dla całej tabeli albo trzymać `manifest` z hashem znanych ID.

### 6.4. Klucz w pamięci procesu
Klucz Fernet leży w atrybutach obiektu Pythonowego. Python nie ma bezpiecznego wymazywania pamięci; atakujący z dostępem do procesu (np. przez debugger) może go wyciągnąć. Kompletne rozwiązanie wymagałoby `mlock`+ `ctypes` do wyzerowania bajtów przy wylogowaniu — na tym poziomie wchodzimy jednak w rozwiązania OS-specific.

### 6.5. Porównanie hashów przez `==`
Timing-safe porównanie byłoby ładne. `hmac.compare_digest(a, b)`.

### 6.6. Brak limitu prób logowania
Nie ma rate-limitingu na `_login_master_password`. W praktyce, dla aplikacji lokalnej, jest to broniące się słabo (atakujący z dostępem do pliku może i tak robić brute-force offline poza aplikacją). Jednak dodanie opóźnienia (sleep 1s) po nieudanym logowaniu zniechęca do przypadkowych prób.

### 6.7. Notatki są opcjonalne, ale niezaszyfrowane
Pole `notes` w tabeli `passwords` trzymane jest jako plain-text `TEXT`. Zaszyfrowanie go tym samym mechanizmem, co hasła, byłoby proste (i zalecane).

---

## 7. Diagram przepływu — rejestracja i logowanie

```
Rejestracja:
    plaintext master  ──►  os.urandom(16) = salt
                       ──►  PBKDF2(200k) ──► base64 ──► master_hash
                       ──►  zapis (master_hash, salt) w tabeli `users`

Logowanie:
    plaintext master  ──►  odczyt salt z bazy
                       ──►  PBKDF2(200k) ──► base64 ──► computed_hash
                       ──►  computed_hash == stored_hash ?
                            └─► TAK:  self.crypto_manager = CryptoManager(master, salt)
                                       (klucz Fernet w RAM, nie na dysk)
                            └─► NIE:  komunikat błędu

Dodanie hasła:
    plaintext password  ──►  Fernet(key).encrypt() ──► bytes (BLOB)
                          ──►  zapis w tabeli `passwords`

Kopiowanie hasła:
    encrypted_password (BLOB)  ──►  Fernet(key).decrypt() ──► plaintext
                                 ──►  pyperclip.copy(plaintext)
                                 ──►  after(20s) ──► pyperclip.copy("")
```

---

## 8. Podsumowanie

Aplikacja jest przykładem **defense in depth** — bezpieczeństwo nie zależy od pojedynczego mechanizmu, ale od warstw:

1. **Kryptografia** — silny KDF + uwierzytelnione szyfrowanie (Fernet = AES-CBC + HMAC).
2. **Higiena UX** — auto-blokada, auto-czyszczenie schowka, ostrzeżenia przed destrukcyjnymi akcjami.
3. **Odporność na błędy** — atomowe operacje z transakcjami przy zmianie hasła głównego.
4. **Bezpieczne domyślne wartości** — generator używa `secrets`, sól z `os.urandom`, sensowne minimalne długości.
5. **Ograniczenie powierzchni ataku** — brak sieci, brak zewnętrznych zależności runtime poza standardowymi bibliotekami krypto.

Główne pola do rozwoju to migracja na Argon2id, podniesienie iteracji PBKDF2 do rekomendowanej wartości i szyfrowanie notatek.
