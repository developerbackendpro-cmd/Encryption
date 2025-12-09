import os
import base64
import zipfile
import getpass
from aiogram.types import InputFile
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from aiogram import Bot, Dispatcher
from aiogram.utils import executor
from aiogram.dispatcher import FSMContext
from aiogram.contrib.fsm_storage.memory import MemoryStorage
from aiogram.dispatcher.filters.state import State, StatesGroup
from aiogram import types

API_TOKEN = '8023296312:AAFZvasvkaPKwvmfkPHXf5Q7AmoDaJLSvNg'

bot = Bot(token=API_TOKEN)
dp = Dispatcher(bot, storage=MemoryStorage())

class Encrypt(StatesGroup):
    password = State()
    file = State()

def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    return key

def encrypt_file(file_name: str, key: bytes):
    fernet = Fernet(key)
    with open(file_name, 'rb') as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    with open(file_name + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

def zip_image(image_path: str, zip_path: str):
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        zipf.write(image_path, os.path.basename(image_path))

def zip_and_encrypt_image(image_path: str, passphrase: str):
    salt = b'some_random_salt'
    zip_path = image_path + '.zip'
    zip_image(image_path, zip_path)
    key = derive_key(passphrase, salt)
    encrypt_file(zip_path, key)
    os.remove(zip_path)
    return zip_path + '.enc'

@dp.message_handler(commands=['start'], state='*')
async def order_start(message: types.Message, state: FSMContext):
    await state.finish()
    await state.reset_state(with_data=True)
    await message.answer("Iltimos, shifrlash uchun kalit so'z yuborin !")
    await Encrypt.password.set()

@dp.message_handler(state=Encrypt.password)
async def process_name(message: types.Message, state: FSMContext):
    async with state.proxy() as data:
        data['password'] = message.text
    await message.answer("Shifrlamoqchi bo'lgan faylizni yuborin !")
    await Encrypt.file.set()

@dp.message_handler(content_types=['document'], state=Encrypt.file)
async def handle_document(message: types.Message, state: FSMContext):
    user_data = await state.get_data()
    password = user_data.get('password')
    document = message.document
    file_info = await bot.get_file(document.file_id)
    file_path = file_info.file_path
    file_name = document.file_name
    downloaded_file = await bot.download_file(file_path)
    with open(file_name, 'wb') as new_file:
        new_file.write(downloaded_file.getvalue())
    passphrase = f'{password}'
    encrypted_file_path = zip_and_encrypt_image(file_name, passphrase)
    with open(encrypted_file_path, 'rb') as encrypted_file:
        await bot.send_document(message.chat.id, InputFile(encrypted_file, filename=os.path.basename(encrypted_file_path)))
    os.remove(file_name)
    os.remove(encrypted_file_path)
    await message.answer('fayil shifrlandi !!!')

if __name__ == '__main__':
    executor.start_polling(dp, skip_updates=True)
