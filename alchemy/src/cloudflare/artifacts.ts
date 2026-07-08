/**
 * Properties for creating an Artifacts binding.
 *
 * Artifacts namespaces are created implicitly by Cloudflare when the first
 * repository is created in the namespace, so this binding does not provision
 * or delete a namespace resource.
 */
export interface ArtifactsProps {
  /**
   * Artifacts namespace name.
   */
  namespace: string;

  dev?: {
    /**
     * Whether to run the Artifacts binding remotely in local development.
     *
     * Artifacts do not have a local emulator, so generated Wrangler config
     * defaults this binding to remote mode.
     *
     * @default true
     */
    remote?: boolean;
  };
}

/**
 * Cloudflare Artifacts binding.
 *
 * Artifacts namespaces are implicit containers for repositories. Use this
 * helper to bind a Worker to a namespace; repository lifecycle should be
 * managed through the Artifacts runtime API, REST API, or Git endpoint.
 *
 * @example
 * ```ts
 * import { Artifacts, Worker } from "alchemy/cloudflare";
 *
 * await Worker("site-editor", {
 *   entrypoint: "./src/worker.ts",
 *   bindings: {
 *     SITE_ARTIFACTS: Artifacts({ namespace: "my-sites" }),
 *   },
 * });
 * ```
 *
 * @see https://developers.cloudflare.com/artifacts/
 */
export interface Artifacts {
  type: "artifacts";
  namespace: string;
  dev?: {
    remote?: boolean;
  };
}

export function Artifacts(props: string | ArtifactsProps): Artifacts {
  if (typeof props === "string") {
    return {
      type: "artifacts",
      namespace: props,
    };
  }

  return {
    type: "artifacts",
    namespace: props.namespace,
    dev: props.dev,
  };
}
