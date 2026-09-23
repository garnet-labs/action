import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import test from "node:test"
import {
    buildRunReview,
    exportReviewModel,
    renderRunReview,
    renderStepSummary,
    summarizeProfile,
} from "../src/runtime-review.js"

const fixture = JSON.parse(readFileSync(
    new URL("./fixtures/renderer-testdata/real/local-network-evidence.json", import.meta.url), "utf8",
))

function reviewFor(profiles, options = {}) {
    return buildRunReview({
        repo: "example/renderer-fixture",
        sha: fixture.commit,
        jobs: profiles.map(summarizeProfile),
        ...options,
    })
}

function machineSummary(body) {
    return JSON.parse(body.match(/<!-- garnet:summary (.*?) -->/)[1])
}

test("sanitized observed local evidence survives projection, model export and both rendered surfaces", () => {
    assert.equal(fixture.profiles.length, 1)
    for (const profile of fixture.profiles) {
        const job = summarizeProfile(profile)
        assert.equal(job.edges.length, 0)
        assert.equal(job.local_edges.length, 2)
        assert.deepEqual(job.local_edges.map(edge => edge.remote_address).sort(), ["127.0.0.1", "::1"])
        assert.ok(job.local_edges.every(edge => edge.process === "sckit" && edge.result === "attention"))
        assert.equal(job.counts.destinations, 0)
        const review = reviewFor([profile])
        const model = exportReviewModel(review)
        assert.equal(model.jobs[0].local_edges.length, 2)
        assert.ok(model.jobs[0].local_edges.every(edge => !("executable" in edge)))
        for (const body of [renderRunReview(review), renderStepSummary([profile])]) {
            assert.match(body, /Local network evidence \(current record; not outbound\)/)
            assert.match(body, /sckit/)
            assert.match(body, /detection: hidden_elf_exec/)
            assert.match(body, /detection: exec_from_unusual_dir/)
            assert.match(body, /dns resolver/)
        }
        const summary = machineSummary(renderRunReview(review))
        assert.equal(summary.destinations, 0)
        assert.deepEqual(summary.localEvidence, { version: 1, associations: 2, comparison: "not-compared" })
    }
})

test("the fixture isolates the observed omission to the local projection", () => {
    const profile = structuredClone(fixture.profiles[0])
    delete profile.data.network.local
    assert.doesNotMatch(renderRunReview(reviewFor([profile])), /sckit|hidden_elf_exec/)
    assert.doesNotMatch(renderStepSummary([profile]), /sckit|hidden_elf_exec/)
})

test("local evidence remains visible with unchanged outbound activity; no outbound delta is fabricated", () => {
    const current = structuredClone(fixture.profiles[0])
    current.data.network.egress = { peers: [{
        remote_address: "192.0.2.1",
        remote_names: ["registry.example"],
        proc_trees: [{ process: "npm", ancestry: ["Runner.Worker", "npm"] }],
    }] }
    const previous = structuredClone(current)
    delete previous.data.network.local
    const review = reviewFor([current], {
        previousSha: "a".repeat(40),
        previousJobs: [summarizeProfile(previous)],
    })
    const body = renderRunReview(review)
    assert.match(body, /sckit/)
    assert.match(body, /outbound-only/)
    const summary = machineSummary(body)
    assert.equal(summary.added, 0)
    assert.equal(summary.removed, 0)
    assert.equal(summary.changed, 0)
    assert.equal(summary.destinations, 1)
})

test("local and egress peers with the same identity cannot merge or borrow attribution", () => {
    const profile = structuredClone(fixture.profiles[0])
    const peer = structuredClone(profile.data.network.local.peers[0])
    peer.proc_trees = [{ process: "outbound-client", ancestry: ["Runner.Worker", "outbound-client"] }]
    peer.detections = ["flow"]
    profile.data.network.egress = { peers: [peer] }
    const review = reviewFor([profile])
    assert.equal(review.jobs[0].edges.length, 1)
    assert.equal(review.jobs[0].local_edges.length, 2)
    const body = renderRunReview(review)
    const localSection = body.slice(body.indexOf("<strong>Local network evidence"))
    assert.match(localSection, /sckit/)
    assert.doesNotMatch(localSection, /outbound-client/)
    assert.equal(machineSummary(body).destinations, 1)
})

test("a benign client of the same resolver cannot deduplicate away a detected process", () => {
    const profile = structuredClone(fixture.profiles[0])
    const peer = structuredClone(profile.data.network.local.peers[0])
    peer.proc_trees = [{ process: "benign-client", ancestry: ["Runner.Worker", "benign-client"] }]
    peer.detections = ["flow"]
    peer.result = "pass"
    profile.data.network.local.peers.unshift(peer)
    const body = renderRunReview(reviewFor([profile]))
    assert.match(body, /benign-client/)
    assert.match(body, /sckit/)
    assert.match(body, /hidden_elf_exec/)
})

test("missing, null and malformed local containers preserve the existing egress-only output", () => {
    const profile = structuredClone(fixture.profiles[0])
    delete profile.data.network.local
    const expected = renderRunReview(reviewFor([profile]))
    assert.equal("localEvidence" in machineSummary(expected), false)
    for (const local of [null, {}, { peers: null }, { peers: {} }, { peers: [] }]) {
        profile.data.network.local = local
        assert.equal(renderRunReview(reviewFor([profile])), expected)
        assert.equal(summarizeProfile(profile).local_edges.length, 0)
    }
    profile.data.network.local = { peers: [null, {}, { proc_trees: [] }] }
    assert.doesNotThrow(() => renderRunReview(reviewFor([profile])))
})

test("local record strings are escaped and argv/full executable paths are never rendered", () => {
    const profile = structuredClone(fixture.profiles[0])
    const peer = profile.data.network.local.peers[0]
    peer.proc_trees[0].process = "<script>alert(1)</script>"
    peer.proc_trees[0].ancestry = ["Runner.Worker", "<script>alert(1)</script>"]
    peer.proc_trees[0].arguments = "SECRET_ARGV"
    peer.proc_trees[0].executable = "/opt/example/PRIVATE_FULL_PATH/sckit"
    peer.detections = ["<img src=x onerror=alert(1)>"]
    for (const body of [renderRunReview(reviewFor([profile])), renderStepSummary([profile])]) {
        assert.doesNotMatch(body, /<script>|<img src=x|SECRET_ARGV|PRIVATE_FULL_PATH/)
        assert.match(body, /&lt;script&gt;/)
    }
    const review = reviewFor([profile])
    review.jobs[0].local_edges[0].arguments = "SECRET_ARGV"
    review.jobs[0].local_edges[0].extra_metadata = "UNEXPECTED_METADATA"
    assert.doesNotMatch(JSON.stringify(exportReviewModel(review)), /SECRET_ARGV|PRIVATE_FULL_PATH|UNEXPECTED_METADATA/)
})

test("local peers render deterministically and budget truncation is explicit", () => {
    const profile = structuredClone(fixture.profiles[0])
    const expected = renderRunReview(reviewFor([profile]))
    profile.data.network.local.peers.reverse()
    assert.equal(renderRunReview(reviewFor([profile])), expected)
    const reduced = renderRunReview(reviewFor([profile]), { budget: 900 })
    assert.ok(Buffer.byteLength(reduced) <= 900)
    assert.match(reduced, /rendered 0 of 2 local destination associations/)
})

test("the public fixture contains only synthetic identifiers and whitelisted telemetry fields", () => {
    assert.deepEqual(Object.keys(fixture).sort(), ["commit", "description", "profiles"])
    for (const profile of fixture.profiles) {
        assert.deepEqual(Object.keys(profile).sort(), ["data", "id"])
        assert.equal(profile.data.scenarios.github.repository, "example/renderer-fixture")
        assert.equal(profile.data.scenarios.github.run_id, "1")
        assert.equal(profile.data.scenarios.github.sha, "b".repeat(40))
        for (const peer of profile.data.network.local.peers) {
            assert.deepEqual(Object.keys(peer).sort(), [
                "detections", "proc_trees", "protocol", "remote_address", "remote_names", "remote_ports", "result",
            ])
            for (const tree of peer.proc_trees) {
                assert.deepEqual(Object.keys(tree).sort(), ["ancestry", "github_step", "pid", "process"])
                assert.equal(tree.pid, 4242)
            }
        }
    }
})
