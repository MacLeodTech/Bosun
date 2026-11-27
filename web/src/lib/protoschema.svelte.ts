// The project's .proto schema. It is kept in the project (`/proto/schema`) and sent along with Decoder requests for
// protobuf and gRPC bodies, so the message viewer, the Repeater and the Decoder all show the same field names.
import { api } from './api';
import { session } from './session.svelte';
import type { components } from './api-types';

type Reply = components['schemas']['ProtoSchema'];

class ProtoSchema {
  source = $state('');
  messages = $state<string[]>([]);
  calls = $state<string[]>([]);
  private started = false;

  /** Load the schema once; reload when another project is opened. */
  ensure() {
    if (this.started) return;
    this.started = true;
    void this.load();
    session.on((e) => { if (e.type === 'reload') void this.load(); });
  }

  private take(r: Reply) {
    this.source = r.source;
    this.messages = r.messages ?? [];
    this.calls = r.calls ?? [];
  }

  async load() {
    try { this.take(await api.get<Reply>('/proto/schema')); } catch { /* no access: no schema */ }
  }

  /** Replace the project's schema; throws with the server's reason when it does not parse. */
  async save(source: string) {
    this.take(await api.put<Reply>('/proto/schema', { source }));
  }

  /** What to add to a Decoder request so its gRPC steps name fields: nothing when there is no schema. */
  forCall(path: string | undefined, response: boolean): { schema?: string; rpc?: string; response?: boolean } {
    return this.source && path ? { schema: this.source, rpc: path, response } : {};
  }
}

export const protoSchema = new ProtoSchema();
