import { defineConfig } from '@hey-api/openapi-ts';

export default defineConfig({
  input: './dist/docs/openapi.yaml',
  output: {
    path: 'app/react/portainer/generated-api/portainer',
    clean: true,
    entryFile: false,
  },
  parser: {
    filters: {
      tags: {
        exclude: ['edge_agent'],
      },
      deprecated: false,
    },
  },
  plugins: [
    {
      enums: 'javascript',
      name: '@hey-api/typescript',
    },
    {
      name: '@hey-api/sdk',
      validator: true,
    },
    {
      name: '@hey-api/client-axios',
      runtimeConfigPath: '@/react/portainer/services/axios/configure-hey-api',
      baseUrl: 'api',
      throwOnError: true,
    },
    {
      name: 'zod',
    },
  ],
});
