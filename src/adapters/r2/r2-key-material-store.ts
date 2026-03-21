import type { KeyMaterialStore } from "../../domain/keys/key-material-store";

export class R2KeyMaterialStore implements KeyMaterialStore {
  constructor(private readonly bucket: R2Bucket) {}

  async get(key: string): Promise<string | null> {
    const object = await this.bucket.get(key);

    return object === null ? null : object.text();
  }

  async put(key: string, value: string): Promise<void> {
    await this.bucket.put(key, value, {
      httpMetadata: {
        contentType: "application/json"
      }
    });
  }
}
