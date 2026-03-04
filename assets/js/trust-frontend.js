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
 * - GitHub verification (redirect approach)
 * 
 * @version 2.3.0
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

        // Check for GitHub callback parameters (for redirect approach)
        const urlParams = new URLSearchParams(window.location.search);
        const githubVerified = urlParams.get('github_verified');
        
        if (githubVerified === 'success') {
            showMessage($('.bcc-trust-wrapper').first(), 
                '✓ GitHub account verified successfully! Your trust score has been updated.', 
                false, 5000);
            
            // Clean up URL
            const newUrl = window.location.pathname + window.location.hash;
            window.history.replaceState({}, document.title, newUrl);
        } else if (githubVerified === 'error') {
            showMessage($('.bcc-trust-wrapper').first(), 
                '❌ GitHub verification failed. Please try again.', 
                true, 8000);
            
            // Clean up URL
            const newUrl = window.location.pathname + window.location.hash;
            window.history.replaceState({}, document.title, newUrl);
        }
    });

    /**
     * Wait for fingerprint to be ready
     * @returns {Promise}
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
     * @param {jQuery} wrapper - The widget wrapper element
     */
    function initializeWidget(wrapper) {
        const pageId = parseInt(wrapper.data('page-id') || wrapper.data('target'));
        
        console.log('BCC Trust: Initializing widget for page', pageId);
        
        if (!pageId || isNaN(pageId)) {
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
     * @param {number} pageId - The page ID
     * @param {jQuery} wrapper - The widget wrapper element
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

            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }

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
     * @param {number} pageId - The page ID
     * @param {jQuery} wrapper - The widget wrapper element
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

            if (!response.ok) {
                return;
            }

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
     * @param {jQuery} wrapper - The widget wrapper element
     * @param {Object} data - The score data
     */
    function updatePageScoreDisplay(wrapper, data) {
        // Update main score with animation
        const currentScore = parseFloat(wrapper.find('.bcc-score-value').text());
        const newScore = parseFloat(data.total_score);
        
        if (!isNaN(currentScore) && !isNaN(newScore) && currentScore !== newScore) {
            animateScoreChange(wrapper, currentScore, newScore);
        } else if (!isNaN(newScore)) {
            wrapper.find('.bcc-score-value').text(newScore.toFixed(1));
        }
        
        // Update reputation tier
        const tierEl = wrapper.find('.bcc-tier-label');
        if (tierEl.length && data.reputation_tier) {
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
        if (progressBar.length && !isNaN(newScore)) {
            progressBar.css('width', newScore + '%');
        }

        // Clear any error messages
        wrapper.find('.bcc-status-message').text('');
    }

    /**
     * Animate score change
     * @param {jQuery} wrapper - The widget wrapper element
     * @param {number} oldValue - The old score value
     * @param {number} newValue - The new score value
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
     * @param {jQuery} wrapper - The widget wrapper element
     * @param {string} message - The message to show
     * @param {boolean} isError - Whether this is an error message
     * @param {number} duration - How long to show the message in ms
     */
    function showMessage(wrapper, message, isError = false, duration = 5000) {
        const messageEl = wrapper.find('.bcc-status-message');
        messageEl.html(message)
            .css('color', isError ? '#f44336' : '#4caf50')
            .fadeIn(300);
        
        // Auto-clear after duration
        if (duration > 0) {
            setTimeout(() => {
                messageEl.fadeOut(300, function() {
                    $(this).html('').css('color', '#666').show();
                });
            }, duration);
        }
    }

    /**
     * Handle page vote action with fingerprint
     * @param {jQuery} wrapper - The widget wrapper element
     * @param {number} pageId - The page ID
     * @param {number} voteType - The vote type (1 for upvote, -1 for downvote)
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

            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }

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
     * @param {jQuery} wrapper - The widget wrapper element
     * @param {number} pageId - The page ID
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

            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }

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
     * @param {jQuery} wrapper - The widget wrapper element
     * @param {number} pageId - The page ID
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

            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }

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
     * @param {jQuery} wrapper - The widget wrapper element
     * @param {number} pageId - The page ID
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

            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }

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
     * Handle GitHub Connect (redirect approach - no popup)
     * @param {jQuery} wrapper - The widget wrapper element
     */
    async function handleGitHubConnect(wrapper) {
        const connectButton = wrapper.find('.bcc-github-connect');
        
        try {
            connectButton.prop('disabled', true).text('Redirecting to GitHub...');
            wrapper.find('.bcc-status-message').text('');

            console.log('BCC Trust: Starting GitHub connection');

            const response = await fetch(window.bccTrust.rest_url + 'github/auth', {
                method: 'GET',
                credentials: 'same-origin',
                headers: {
                    'X-WP-Nonce': window.bccTrust.nonce,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }

            const result = await response.json();
            console.log('BCC Trust: GitHub auth response', result);

            if (result.success && result.data?.auth_url) {
                // Store current page URL to return to after verification
                sessionStorage.setItem('bcc_github_return_url', window.location.href);
                
                // REDIRECT to GitHub (no popup)
                window.location.href = result.data.auth_url;
            } else {
                throw new Error(result.message || 'Failed to get GitHub auth URL');
            }
        } catch (error) {
            console.error('BCC Trust: GitHub connect error', error);
            showMessage(wrapper, 'Connection failed: ' + error.message, true, 5000);
            connectButton.prop('disabled', false).text('Connect GitHub Account');
        }
    }

    /**
     * Check GitHub connection status
     * @param {jQuery} wrapper - The widget wrapper element
     */
    async function checkGitHubStatus(wrapper) {
        try {
            const response = await fetch(window.bccTrust.rest_url + 'github/status', {
                method: 'GET',
                credentials: 'same-origin',
                headers: {
                    'X-WP-Nonce': window.bccTrust.nonce,
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) return;
            
            const result = await response.json();
            
            if (result.success && result.data?.connected) {
                showMessage(wrapper, '✓ GitHub connected successfully!', false, 3000);
                // Reload to show connected state
                setTimeout(() => {
                    location.reload();
                }, 1500);
            } else {
                // Not connected, re-enable the button
                $('.bcc-github-connect').prop('disabled', false).text('Connect GitHub Account');
            }
        } catch (error) {
            console.error('Failed to check GitHub status:', error);
            $('.bcc-github-connect').prop('disabled', false).text('Connect GitHub Account');
        }
    }

    /**
     * Handle GitHub disconnect
     * @param {jQuery} wrapper - The widget wrapper element
     */
    async function handleGitHubDisconnect(wrapper) {
        const disconnectButton = wrapper.find('.bcc-github-disconnect');
        
        if (!confirm('Are you sure you want to disconnect your GitHub account? This may affect your trust score.')) {
            return;
        }
        
        try {
            disconnectButton.prop('disabled', true).text('Disconnecting...');
            wrapper.find('.bcc-status-message').text('');

            console.log('BCC Trust: Disconnecting GitHub');

            const response = await fetch(window.bccTrust.rest_url + 'github/disconnect', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'X-WP-Nonce': window.bccTrust.nonce,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }

            const result = await response.json();
            console.log('BCC Trust: GitHub disconnect response', result);

            if (result.success) {
                showMessage(wrapper, '✓ GitHub disconnected', false, 3000);
                
                // Reload the page after a short delay
                setTimeout(() => {
                    location.reload();
                }, 1500);
            } else {
                throw new Error(result.message || 'Failed to disconnect GitHub');
            }
        } catch (error) {
            console.error('BCC Trust: GitHub disconnect error', error);
            showMessage(wrapper, 'Disconnect failed: ' + error.message, true, 5000);
            disconnectButton.prop('disabled', false).text('Disconnect');
        }
    }

    /**
     * Event delegation for trust widgets
     */
    $(document).on('click', '.bcc-trust-wrapper button', function(e) {
        e.preventDefault();
        
        const wrapper = $(this).closest('.bcc-trust-wrapper');
        const pageId = parseInt(wrapper.data('page-id') || wrapper.data('target'));
        const button = $(this);
        
        console.log('BCC Trust: Button clicked', {
            pageId: pageId,
            buttonText: button.text().trim(),
            buttonClass: button.attr('class'),
            isVote: button.hasClass('bcc-vote-button'),
            isEndorse: button.hasClass('bcc-endorse-button'),
            isGitHub: button.hasClass('bcc-github-connect') || button.hasClass('bcc-github-disconnect')
        });

        if (!pageId || isNaN(pageId)) {
            showMessage(wrapper, 'Error: Page ID not found', true);
            return;
        }

        // Check login status for vote/endorse buttons only
        if (!window.bccTrust.logged_in && 
            (button.hasClass('bcc-vote-button') || button.hasClass('bcc-endorse-button'))) {
            const loginUrl = window.bccTrust.login_url || '/wp-login.php';
            showMessage(wrapper, 'Please <a href="' + loginUrl + '?redirect_to=' + encodeURIComponent(window.location.href) + '">log in</a> to vote', true, 5000);
            return;
        }

        // Vote buttons
        if (button.hasClass('bcc-vote-button')) {
            const voteType = parseInt(button.data('type'));
            
            // If clicking active vote, remove it
            if (button.hasClass('active')) {
                handleRemovePageVote(wrapper, pageId);
            } else {
                handlePageVote(wrapper, pageId, voteType);
            }
            return;
        }

        // Endorse/Revoke button
        if (button.hasClass('bcc-endorse-button')) {
            if (button.hasClass('revoke')) {
                handleRevokePageEndorsement(wrapper, pageId);
            } else {
                handlePageEndorsement(wrapper, pageId);
            }
            return;
        }

        // GitHub Connect button
        if (button.hasClass('bcc-github-connect')) {
            handleGitHubConnect(wrapper);
            return;
        }

        // GitHub Disconnect button
        if (button.hasClass('bcc-github-disconnect')) {
            handleGitHubDisconnect(wrapper);
            return;
        }
    });

    // Handle dynamic content loading
    $(document).on('bccTrustWidgetAdded', function(e, wrapper) {
        initializeWidget($(wrapper));
    });

})(jQuery);