# Алгоритм MD5

Він забезпечує стійкий хеш-код для повідомлень, і зазвичай використовується для перевірки цілісності даних.

Послідовність дій для обрахунку хешу:

1. Ініціалізація. Задаються початкові значення для хеш-функції. Це чотири 32-бітні числа: 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476.

2. Підготовка повідомлення. Повідомлення доповнюється так, щоб його довжина стала кратною 64 байтам. Доповнення включає додавання одного байта зі значенням 0x80, додавання нульових байтів, які заповнюють простір до 56 байтів, та додавання 64-бітного числа, яке представляє довжину повідомлення в бітах.

3. Розділення повідомлення на блоки. Після підготовки повідомлення воно розбивається на блоки по 64 байти (512 бітів) кожен.

4. Обробка кожного блоку. Кожен блок обробляється окремо. Виконується набір раундів, кожний з яких має певні операції і коефіцієнти.
   - У кожному раунді виконується 64 ітерації;
   - Кожна ітерація включає операції, такі як логічні функції AND, OR, XOR, а також логічне НЕ;
   - Здійснюється ліве обертання 32-бітних значень;
   - Застосовуються константи та функції, що змінюються для кожної ітерації.

5. Обчислення хешу. Після обробки всіх блоків отримуємо кінцевий результат, який складається з чотирьох 32-бітних чисел. Це є значенням хешу.

6. Представлення хешу. Кінцеве значення хешу перетворюється в шістнадцятковий формат (hexadecimal) для зручності відображення.