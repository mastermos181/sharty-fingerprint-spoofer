// ==UserScript==
// @name        sharty prevent post deletion
// @namespace   Violentmonkey Scripts
// @description Prevents post deletion with auto thread update enabled
// @match       https://soyjak.st/*/thread/*.html*
// @grant       none
// @version     1.0
// @author      -
// @run-at      document-start
// ==/UserScript==

(() => {
'use strict';

const style = document.createElement('style');
style.textContent = `
    .deleted-notice {
        color: red;
        margin-left: 8px;
    }
`;
(document.head || document.documentElement).appendChild(style);

// This function will contain the core logic to patch jQuery's AJAX functionality.
const patchJQueryAjax = (originalAjax) => {
    // Ensure the original ajax function exists before proceeding.
    if (!originalAjax) {
        return;
    }

    // Overwrite the global jQuery.ajax function.
    window.jQuery.ajax = function(options) {
        // We are only interested in the thread updater's AJAX call.
        if (options.success && options.url && options.url === document.location) {
            const originalSuccess = options.success;

            // Wrap the original success callback to intercept the response.
            options.success = function(data, textStatus, jqXHR) {
                const isPartialView = document.location.href.includes('+');

                const newPostElems = window.jQuery(data).find('div.post.reply');
                const newPostIds = newPostElems.map(function() { return window.jQuery(this).attr('id'); }).get();
                const newPostIdsSet = new Set(newPostIds);

                const currentPostElems = window.jQuery('div.post.reply');
                const currentPostIds = currentPostElems.map(function() { return window.jQuery(this).attr('id'); }).get();

                // Sort current posts into "disappeared" and "remaining"
                const disappearedPostIds = [];
                const remainingPostIds = [];
                for (const id of currentPostIds) {
                    if (id) {
                        if (newPostIdsSet.has(id)) {
                            remainingPostIds.push(id);
                        } else {
                            disappearedPostIds.push(id);
                        }
                    }
                }

                if (disappearedPostIds.length === 0) {
                    // No posts disappeared, execute original success and return
                    return originalSuccess.apply(this, arguments);
                }

                let conclusivelyDeletedIds = new Set();

                if (!isPartialView) {
                    // Full view: any disappeared post is a deleted post.
                    conclusivelyDeletedIds = new Set(disappearedPostIds);
                } else {
                    // Partial view: apply heuristics.
                    const getPostNum = (id) => parseInt(id.replace('reply_', ''));

                    // "Annihilation" Rule: Detects when all visible posts are deleted.
                    if (currentPostIds.length > 0 && newPostIds.length === 0) {
                        conclusivelyDeletedIds = new Set(disappearedPostIds);
                    } else {
                        // Pre-calculate all necessary number arrays for the other heuristics
                        const currentPostNums = currentPostIds.map(getPostNum).sort((a, b) => a - b);
                        const newPostNums = newPostIds.map(getPostNum).sort((a, b) => a - b);
                        const disappearedPostNums = disappearedPostIds.map(getPostNum);
                        const remainingPostNums = remainingPostIds.map(getPostNum).sort((a, b) => a - b);

                        // "Contraction" Rule: Detects deletions at the top when the list doesn't grow.
                        if (currentPostNums.length > 0 && newPostNums.length > 0) {
                            const minCurrentNum = currentPostNums[0];
                            const maxCurrentNum = currentPostNums[currentPostNums.length - 1];
                            const minNewNum = newPostNums[0];
                            const maxNewNum = newPostNums[newPostNums.length - 1];

                            if (minNewNum > minCurrentNum && maxNewNum <= maxCurrentNum) {
                                for (const disappearedNum of disappearedPostNums) {
                                    if (disappearedNum < minNewNum) {
                                        conclusivelyDeletedIds.add('reply_' + disappearedNum);
                                    }
                                }
                            }
                        }

                        // "Order" Rule: If a disappeared post is newer than the oldest *remaining* post, it must have been deleted.
                        if (remainingPostNums.length > 0) {
                            const minRemainingNum = remainingPostNums[0];
                            for (const disappearedNum of disappearedPostNums) {
                                if (disappearedNum > minRemainingNum) {
                                    conclusivelyDeletedIds.add('reply_' + disappearedNum);
                                }
                            }
                        }

                        // "Gap" Rule: Check for non-sequential post numbers in the new set of posts.
                        for (let i = 0; i < newPostNums.length - 1; i++) {
                            const currentNum = newPostNums[i];
                            const nextNum = newPostNums[i+1];
                            if (nextNum > currentNum + 1) {
                                // There's a gap. Find which of the disappeared posts belong in this gap.
                                for (const disappearedNum of disappearedPostNums) {
                                    if (disappearedNum > currentNum && disappearedNum < nextNum) {
                                        conclusivelyDeletedIds.add('reply_' + disappearedNum);
                                    }
                                }
                            }
                        }
                    }
                }

                const originalRemove = window.jQuery.fn.remove;

                // Temporarily override jQuery's .remove() function.
                window.jQuery.fn.remove = function() {
                    // Iterate over each element that is targeted for removal.
                    this.each(function() {
                        const elem = window.jQuery(this);
                        let shouldBeRemoved = true;

                        if (elem.is('div.post.reply:not(.you)')) {
                            const elemId = elem.attr('id');
                            if (conclusivelyDeletedIds.has(elemId)) {
                                shouldBeRemoved = false; // Prevent removal
                                // Mark as deleted if not already marked
                                if (elem.find('.intro .deleted-notice').length === 0) {
                                    elem.find('p.intro a.post_no:last').after('<span class="deleted-notice">[Deleted]</span>');
                                }
                            }
                        }
                        // Also protect the <br> tag that follows a deleted post
                        else if (elem.is('br.clear')) {
                            const prevPost = elem.prev('div.post.reply:not(.you)');
                            if (prevPost.length > 0 && conclusivelyDeletedIds.has(prevPost.attr('id'))) {
                                shouldBeRemoved = false; // Prevent removal
                            }
                        }

                        if (shouldBeRemoved) {
                            originalRemove.apply(elem); // Use the original remove function.
                        }
                    });

                    return this; // Maintain chainability.
                };

                // Execute the original success callback. It will use our overridden remove function.
                originalSuccess.apply(this, arguments);

                // Restore the original remove function after execution.
                window.jQuery.fn.remove = originalRemove;
            };
        }

        // Execute the original ajax call with our modified options.
        return originalAjax.apply(this, arguments);
    };
    console.log('[sharty prevent post deletion] Patched ajax to prevent post deletion');
};

const attachAjaxHandler = () => {
    if (typeof window.jQuery !== 'undefined' && typeof window.jQuery.ajax !== 'undefined') {
        patchJQueryAjax(window.jQuery.ajax);
        return true;
    }
    return false;
};

const maxWaitTime = 10000; // 10 seconds
const startTime = Date.now();
const jqueryCheckInterval = setInterval(() => {
    if (attachAjaxHandler()) {
        clearInterval(jqueryCheckInterval);
    } else if ((Date.now() - startTime) > maxWaitTime) {
        clearInterval(jqueryCheckInterval);
        console.error('[sharty prevent post deletion] Timed out waiting for jQuery ($) to become available. Ajax not patched');
    }
}, 100);

})();