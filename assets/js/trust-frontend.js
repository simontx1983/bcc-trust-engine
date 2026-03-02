/**
 * BCC Trust Engine - Frontend Interface
 * 
 * Handles:
 * - Score display for PeepSo Pages
 * - Voting (upvote/downvote)
 * - Endorsements
 * - Device fingerprinting
 * - Fraud prevention
 * - Real-time updates
 */

(function($) {
    'use strict';

    console.log('BCC Trust: Loading...', window.bccTrust || {});

    $(document).ready(function() {
        if (typeof window.bccTrust === "undefined") {
            console.error('BCC Trust: Configuration missing');
            return;
        }

        // Wait for fingerprint to be ready
        waitForFingerprint().then(() => {
            // Auto-initialize on pages with trust widgets
            $('.bcc-trust-wrapper').each(function() {
                initializeWidget($(this));
            });
        });

        // Listen for dynamically added widgets
        $(document).on('bccTrustWidgetAdded', function(e, wrapper) {
            waitForFingerprint().then(() => {
                initializeWidget($(wrapper));
            });
        });
    });

    /**
     * Wait for fingerprint to be ready
     */
    function waitForFingerprint() {
        return new Promise((resolve) => {
            // If fingerprint is already available or not needed
            if (window.bccFingerprinter?.ready || !window.bccTrust.fingerprint_enabled) {
                resolve();
                return;
            }

            // Wait for fingerprint ready event
            document.addEventListener('fingerprintReady', resolve, { once: true });
            
            // Timeout after 3 seconds
            setTimeout(resolve, 3000);
        });
    }

    /**
     * Initialize a trust widget
     */
    function initializeWidget(wrapper) {
        const pageId = parseInt(wrapper.data('page-id') || wrapper.data('target'));
        
        console.log('BCC Trust: Initializing widget for page', pageId);
        
        if (!pageId) {
            console.error('BCC Trust: No page ID found');
            wrapper.find('.bcc-score-value').text('Error');
            wrapper.find('.bcc-status-message').text('Configuration error').css('color', '#f44336');
            return;
        }

        // Store page ID
        wrapper.data('page-id', pageId);

        // Load initial score
        loadPageScore(pageId, wrapper);

        // Check for user's existing vote
        if (window.bccTrust.logged_in) {
            checkUserVote(pageId, wrapper);
        }
    }

    /**
     * Load trust score for a PeepSo page
     */
    async function loadPageScore(pageId, wrapper) {
        try {
            wrapper.find('.bcc-score-value').text('Loading...');
            
            const url = `${window.bccTrust.rest_url}page/${pageId}/score`;
            console.log('Fetching page score:', url);

            const response = await fetch(url, {
                credentials: 'same-origin',
                headers: {
                    'X-WP-Nonce': window.bccTrust.nonce,
                    'Content-Type': 'application/json'
                }
            });

            const data = await response.json();
            
            if (data.success) {
                updatePageScoreDisplay(wrapper, data.data);
                
                // Store initial score for comparison
                wrapper.data('initial-score', data.data.total_score);
            } else {
                throw new Error(data.message || 'Failed to load score');
            }
        } catch (error) {
            console.error('Load error:', error);
            wrapper.find('.bcc-score-value').text('Error');
            showMessage(wrapper, 'Failed to load: ' + error.message, true);
        }
    }

    /**
     * Check if user has already voted
     */
    async function checkUserVote(pageId, wrapper) {
        try {
            const url = `${window.bccTrust.rest_url}page/${pageId}/score`;
            const response = await fetch(url, {
                credentials: 'same-origin',
                headers: {
                    'X-WP-Nonce': window.bccTrust.nonce,
                    'Content-Type': 'application/json'
                }
            });

            const data = await response.json();
            
            if (data.success && data.data.user_vote) {
                const voteType = data.data.user_vote.vote_type;
                const voteButton = wrapper.find(`.bcc-vote-button[data-type="${voteType}"]`);
                voteButton.addClass('active');
                
                // Check for endorsement
                if (data.data.user_endorsed) {
                    wrapper.find('.bcc-endorse-button').addClass('revoke').text('Revoke Endorsement');
                }
            }
        } catch (error) {
            console.error('Failed to check user vote:', error);
        }
    }

    /**
     * Update page score display
     */
    function updatePageScoreDisplay(wrapper, data) {
        // Update main score with animation
        const currentScore = parseFloat(wrapper.find('.bcc-score-value').text());
        const newScore = parseFloat(data.total_score);
        
        if (!isNaN(currentScore) && !isNaN(newScore) && currentScore !== newScore) {
            animateScoreChange(wrapper, currentScore, newScore);
        } else {
            wrapper.find('.bcc-score-value').text(data.total_score);
        }
        
        // Update reputation tier
        const tierEl = wrapper.find('.bcc-tier-label');
        if (tierEl.length) {
            tierEl.text('(' + data.reputation_tier + ')').attr('data-tier', data.reputation_tier);
        }
        
        // Update confidence
        const confidenceEl = wrapper.find('.bcc-confidence-level');
        if (confidenceEl.length && data.confidence_score !== undefined) {
            const confidencePercent = Math.round(data.confidence_score * 100);
            confidenceEl.text(confidencePercent + '% confidence')
                .attr('data-confidence', confidencePercent);
        }

        // Update vote count
        const voteCountEl = wrapper.find('.bcc-vote-total');
        if (voteCountEl.length && data.vote_count !== undefined) {
            voteCountEl.text(data.vote_count + ' vote' + (data.vote_count !== 1 ? 's' : ''));
        }

        // Update endorsement count
        const endorseCountEl = wrapper.find('.bcc-endorsement-total');
        if (endorseCountEl.length && data.endorsement_count !== undefined) {
            endorseCountEl.text(data.endorsement_count + ' endorsement' + (data.endorsement_count !== 1 ? 's' : ''));
        }

        // Update detailed scores
        const positiveEl = wrapper.find('.bcc-positive-score .value');
        if (positiveEl.length && data.positive_score !== undefined) {
            positiveEl.text(data.positive_score.toFixed(1));
        }

        const negativeEl = wrapper.find('.bcc-negative-score .value');
        if (negativeEl.length && data.negative_score !== undefined) {
            negativeEl.text(data.negative_score.toFixed(1));
        }

        // Update progress bar if exists
        const progressBar = wrapper.find('.bcc-score-progress');
        if (progressBar.length) {
            progressBar.css('width', data.total_score + '%');
        }

        // Clear any error messages
        wrapper.find('.bcc-status-message').text('');
    }

    /**
     * Animate score change
     */
    function animateScoreChange(wrapper, oldValue, newValue) {
        const scoreEl = wrapper.find('.bcc-score-value');
        const duration = 1000;
        const startTime = performance.now();
        
        function update(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const currentValue = oldValue + (newValue - oldValue) * progress;
            
            scoreEl.text(currentValue.toFixed(1));
            
            if (progress < 1) {
                requestAnimationFrame(update);
            }
        }
        
        requestAnimationFrame(update);
    }

    /**
     * Show message to user
     */
    function showMessage(wrapper, message, isError = false, duration = 5000) {
        const messageEl = wrapper.find('.bcc-status-message');
        messageEl.text(message)
            .css('color', isError ? '#f44336' : '#4caf50')
            .fadeIn(300);
        
        // Auto-clear after duration
        setTimeout(() => {
            messageEl.fadeOut(300, function() {
                $(this).text('').css('color', '#666').show();
            });
        }, duration);
    }

    /**
     * Handle page vote action with fingerprint
     */
    async function handlePageVote(wrapper, pageId, voteType) {
        const voteButton = wrapper.find(`.bcc-vote-button[data-type="${voteType}"]`);
        
        try {
            voteButton.prop('disabled', true);
            wrapper.find('.bcc-status-message').text('');

            // Get fingerprint data if available
            let fingerprintData = null;
            if (window.bccFingerprinter?.ready) {
                fingerprintData = {
                    hash: window.bccFingerprinter.fingerprint.hash,
                    timestamp: Date.now()
                };
            }

            console.log('BCC Trust: Recording page vote', {pageId, voteType, fingerprint: !!fingerprintData});

            const response = await fetch(window.bccTrust.rest_url + 'vote', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-WP-Nonce': window.bccTrust.nonce
                },
                body: JSON.stringify({
                    page_id: pageId,
                    vote_type: voteType,
                    fingerprint: fingerprintData
                })
            });

            const result = await response.json();
            console.log('BCC Trust: Vote response', result);

            if (response.ok && result.success) {
                updatePageScoreDisplay(wrapper, result.data.score);
                
                // Show weight information
                const weightMsg = result.data.analysis?.weight_applied ?
                    ` (weight: ${result.data.analysis.weight_applied.toFixed(2)}x)` : '';
                showMessage(wrapper, 
                    voteType === 1 ? `✓ Upvote recorded${weightMsg}!` : `✓ Downvote recorded${weightMsg}!`,
                    false, 3000);
                
                // Update active states
                wrapper.find('.bcc-vote-button').removeClass('active');
                voteButton.addClass('active');
                
                // Trigger event for other scripts
                $(document).trigger('bccTrustVoteCast', [pageId, voteType, result]);
            } else {
                throw new Error(result.message || 'Vote failed');
            }
        } catch (error) {
            console.error('BCC Trust: Vote error', error);
            showMessage(wrapper, error.message, true);
        } finally {
            voteButton.prop('disabled', false);
        }
    }

    /**
     * Handle remove page vote
     */
    async function handleRemovePageVote(wrapper, pageId) {
        const activeButton = wrapper.find('.bcc-vote-button.active');
        
        try {
            activeButton.prop('disabled', true);
            wrapper.find('.bcc-status-message').text('');

            console.log('BCC Trust: Removing page vote', {pageId});

            const response = await fetch(window.bccTrust.rest_url + 'remove-vote', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-WP-Nonce': window.bccTrust.nonce
                },
                body: JSON.stringify({
                    page_id: pageId
                })
            });

            const result = await response.json();
            console.log('BCC Trust: Remove vote response', result);

            if (response.ok && result.success) {
                updatePageScoreDisplay(wrapper, result.data.score);
                showMessage(wrapper, '✓ Vote removed', false, 3000);
                wrapper.find('.bcc-vote-button').removeClass('active');
                
                // Trigger event
                $(document).trigger('bccTrustVoteRemoved', [pageId, result]);
            } else {
                throw new Error(result.message || 'Remove failed');
            }
        } catch (error) {
            console.error('BCC Trust: Remove vote error', error);
            showMessage(wrapper, error.message, true);
        } finally {
            activeButton.prop('disabled', false);
        }
    }

    /**
     * Handle page endorsement with fingerprint
     */
    async function handlePageEndorsement(wrapper, pageId) {
        const endorseButton = wrapper.find('.bcc-endorse-button');
        
        try {
            endorseButton.prop('disabled', true);
            wrapper.find('.bcc-status-message').text('');

            // Get fingerprint data if available
            let fingerprintData = null;
            if (window.bccFingerprinter?.ready) {
                fingerprintData = {
                    hash: window.bccFingerprinter.fingerprint.hash,
                    timestamp: Date.now()
                };
            }

            console.log('BCC Trust: Endorsing page', {pageId, fingerprint: !!fingerprintData});

            const response = await fetch(window.bccTrust.rest_url + 'endorse', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-WP-Nonce': window.bccTrust.nonce
                },
                body: JSON.stringify({
                    page_id: pageId,
                    context: 'general',
                    fingerprint: fingerprintData
                })
            });

            const result = await response.json();
            console.log('BCC Trust: Endorse response', result);

            if (response.ok && result.success) {
                updatePageScoreDisplay(wrapper, result.data.score);
                showMessage(wrapper, '✓ Endorsement added!', false, 3000);
                endorseButton.text('Revoke Endorsement').addClass('revoke');
                
                // Trigger event
                $(document).trigger('bccTrustEndorsed', [pageId, result]);
            } else {
                throw new Error(result.message || 'Endorsement failed');
            }
        } catch (error) {
            console.error('BCC Trust: Endorse error', error);
            showMessage(wrapper, error.message, true);
        } finally {
            endorseButton.prop('disabled', false);
        }
    }

    /**
     * Handle revoke page endorsement
     */
    async function handleRevokePageEndorsement(wrapper, pageId) {
        const endorseButton = wrapper.find('.bcc-endorse-button.revoke');
        
        try {
            endorseButton.prop('disabled', true);
            wrapper.find('.bcc-status-message').text('');

            console.log('BCC Trust: Revoking page endorsement', {pageId});

            const response = await fetch(window.bccTrust.rest_url + 'revoke-endorsement', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-WP-Nonce': window.bccTrust.nonce
                },
                body: JSON.stringify({
                    page_id: pageId,
                    context: 'general'
                })
            });

            const result = await response.json();
            console.log('BCC Trust: Revoke response', result);

            if (response.ok && result.success) {
                updatePageScoreDisplay(wrapper, result.data.score);
                showMessage(wrapper, '✓ Endorsement revoked', false, 3000);
                endorseButton.text('⭐ Endorse Page').removeClass('revoke');
                
                // Trigger event
                $(document).trigger('bccTrustEndorsementRevoked', [pageId, result]);
            } else {
                throw new Error(result.message || 'Revoke failed');
            }
        } catch (error) {
            console.error('BCC Trust: Revoke error', error);
            showMessage(wrapper, error.message, true);
        } finally {
            endorseButton.prop('disabled', false);
        }
    }

    /**
     * Event delegation for trust widgets
     */
    $(document).on('click', '.bcc-trust-wrapper button', function(e) {
        e.preventDefault();
        
        const wrapper = $(this).closest('.bcc-trust-wrapper');
        const pageId = parseInt(wrapper.data('page-id') || wrapper.data('target'));
        
        console.log('BCC Trust: Button clicked', {pageId, button: $(this).text()});

        if (!pageId) {
            showMessage(wrapper, 'Error: Page ID not found', true);
            return;
        }

        // Check login status
        if (!window.bccTrust.logged_in) {
            const loginUrl = window.bccTrust.login_url || '/login';
            showMessage(wrapper, 'Please <a href="' + loginUrl + '">log in</a> to vote', true, 5000);
            return;
        }

        // Vote buttons
        if ($(this).hasClass('bcc-vote-button')) {
            const voteType = parseInt($(this).data('type'));
            
            // If clicking active vote, remove it
            if ($(this).hasClass('active')) {
                handleRemovePageVote(wrapper, pageId);
            } else {
                handlePageVote(wrapper, pageId, voteType);
            }
        }

        // Endorse/Revoke button
        if ($(this).hasClass('bcc-endorse-button')) {
            if ($(this).hasClass('revoke')) {
                handleRevokePageEndorsement(wrapper, pageId);
            } else {
                handlePageEndorsement(wrapper, pageId);
            }
        }
    });

    // Handle dynamic content loading
    $(document).on('bccTrustWidgetAdded', function(e, wrapper) {
        initializeWidget($(wrapper));
    });

})(jQuery);