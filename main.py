from asyncio import run
from utils.loader import DataLoader

async def main():
    loader = DataLoader()
    await loader.save()

if __name__ == "__main__":
    run(main())