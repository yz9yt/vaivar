/**
 * vAIvar - Semantic honeypot for attacking AI agents
 * Copyright 2026 vAIvar Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import type { Event } from '../types/events';

type EventSink = {
  readonly name: string;
  accepts: (e: Event) => boolean;
  write: (e: Event) => Promise<void>;
};

export class EventBus {
  private registeredSinks: Map<string, EventSink> = new Map();

  registerSink(sink: EventSink): void {
    this.registeredSinks.set(sink.name, sink);
  }

  unregisterSink(name: string): boolean {
    return this.registeredSinks.delete(name);
  }

  async emit(event: Event): Promise<void> {
    const promises: Promise<void>[] = [];
    
    for (const sink of this.registeredSinks.values()) {
      if (sink.accepts(event)) {
        promises.push(
          sink.write(event).catch((e) => {
            console.error(`Sink ${sink.name} failed:`, e);
          })
        );
      }
    }
    
    await Promise.allSettled(promises);
  }

  async emitMany(events: Event[]): Promise<void> {
    await Promise.all(events.map((e) => this.emit(e)));
  }

  sinks(): EventSink[] {
    return Array.from(this.registeredSinks.values());
  }
}
