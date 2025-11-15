from scanner.input_handler import get_url_from_user

def main():
    try:
        url = get_url_from_user()
        print("[OK] URL recebida:", url)
    except ValueError as e:
        print("Erro:", e)

if __name__ == "__main__":
    main()
