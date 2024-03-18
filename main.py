from asyncio import run
from lib.data.extract import FeatureExtractor

async def main():
    loader = FeatureExtractor()
    await loader.save()

if __name__ == "__main__":
    run(main())