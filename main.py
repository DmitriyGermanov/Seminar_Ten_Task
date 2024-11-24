import re
import hashlib

def check_password_strength(password):
    if len(password) < 8:
        return "Пароль должен быть не менее 8 символов."

    if not re.search(r'[A-Z]', password):
        return "Пароль должен содержать хотя бы одну заглавную букву."
    if not re.search(r'[a-z]', password):
        return "Пароль должен содержать хотя бы одну строчную букву."

    if not re.search(r'\d', password):
        return "Пароль должен содержать хотя бы одну цифру."

    return "Пароль достаточно сложный."

def hash_password(password):
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return hashed_password

if __name__ == "__main__":
    password = input("Введите пароль для проверки: ")
    strength_message = check_password_strength(password)

    if strength_message == "Пароль достаточно сложный.":
        print("Пароль прошел проверку на сложность!")
        hashed_password = hash_password(password)
        print(f"Хэш-значение пароля (SHA-256): {hashed_password}")
    else:
        print(f"Ошибка: {strength_message}")