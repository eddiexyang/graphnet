import assert from 'node:assert/strict'
import test from 'node:test'
import { equal } from '../src/equal.ts'

test('equal matches draft and server-returned network after adding a node or clearing lists', () => {
  const clientBody = {
    id: '00000000000000000000000000000001',
    name: 'prod',
    cidr: '10.42.0.0/16',
    mtu: 1400,
    cipher: 'aes-128-gcm',
    equal_cost_paths: 'lowest-id',
    failure_detection_ms: 0,
    groups: [],
    group_links: [],
    nodes: [
      {
        advertised_subnets: [],
        id: '00000000000000000000000000000010',
        agent_id: '00000000000000000000000000000020',
        name: 'node-a',
        client: false,
        address: '10.42.0.1',
        position: { x: 0, y: 120 },
      },
    ],
    edges: [],
  }
  const controllerNetwork = {
    id: '00000000000000000000000000000001',
    name: 'prod',
    cidr: '10.42.0.0/16',
    mtu: 1400,
    cipher: 'aes-128-gcm',
    last_index: 4,
    nodes: [
      {
        id: '00000000000000000000000000000010',
        index: 4,
        agent_id: '00000000000000000000000000000020',
        name: 'node-a',
        address: '10.42.0.1',
        position: { y: 120, x: 0 },
      },
    ],
    edges: [],
  }
  assert.equal(equal(controllerNetwork, clientBody), true)
  assert.equal(
    equal(controllerNetwork, {
      ...clientBody,
      mtu: 1380,
    }),
    false,
  )
})
