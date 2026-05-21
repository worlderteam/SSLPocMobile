import type { TurboModule } from 'react-native';
import { TurboModuleRegistry } from 'react-native';

export interface Spec extends TurboModule {
  postWithMTLS(
    endpoint: string,
    body: string, 
    headers: Object
  ): Promise<string>;

  getWithMTLS(
    endpoint: string,
    headers: Object
  ): Promise<string>;

  provisionIdentity(): Promise<string>;
}

export default TurboModuleRegistry.getEnforcing<Spec>('SecureNetwork');